// Cloudflare Worker: authenticates on the player's behalf and files a
// ranking submission as a GitHub issue, so the existing
// .github/workflows/ranking.yml action can validate it and update
// ranking-marathon.json / ranking-ta40.json exactly as before.
//
// Anti-cheat: a run must first fetch a signed start token from POST /start
// (issued the moment the player actually presses スタート), then include
// that token when submitting the score/time. The submission is rejected
// unless the claimed result is plausible given the real wall-clock time
// that has actually elapsed since the token was issued. This blocks
// forging a result by POSTing an arbitrary value straight from DevTools
// without ever playing (same pattern as running-ninniku's worker).
//
// Deploy this as-is in the Cloudflare dashboard (Workers & Pages ->
// Create -> paste this file), then add TWO encrypted environment
// variables:
//   - GITHUB_TOKEN: a fine-grained GitHub personal access token scoped
//     ONLY to this repo (pix-co/tetris-ninniku) with "Issues: Read and
//     write" permission (no other scopes needed).
//   - RANKING_SIGNING_KEY: any long random secret string (e.g. 32+ random
//     characters), type "Secret". Only this Worker needs to know it; it
//     is never sent to the client. Used to HMAC-sign start tokens so they
//     can't be forged.

const REPO_OWNER = 'pix-co';
const REPO_NAME = 'tetris-ninniku';
const ALLOWED_ORIGIN = 'https://pix-co.github.io';

const TOKEN_MAX_AGE_MS = 30 * 60 * 1000; // 一時停止等の余裕を見て30分まで有効
const CLOCK_TOLERANCE_MS = 1500;         // タイマー精度・通信遅延の許容誤差(ta40用)

// ta40(40ライン消去タイム、msで小さいほど良い)の絶対下限。
// ハードドロップは即ロックされるため理論上はごく短時間で40ライン消せてしまうが、
// 実際には10ピース以上の受け取り・移動・回転・SRSキック判定などが挟まるため、
// 既存の最速記録(約60秒)を踏まえても3秒を下回ることは現実的にありえない。
const MIN_TA40_MS = 3000;

// marathon(スコア、大きいほど良い)用: 「1ピースあたりに現実的にありえる
// 最大得点」と「1ピースを置くのに最低限かかる時間」から、経過時間(tokenAge)
// に対して理論上あり得る最大スコアを見積もる。誤検知で正規プレイヤーを
// 弾かないよう、あらゆる係数はかなり大きめ(寛容)に取ってある。
//
//   - MIN_MS_PER_PIECE: 1ピースを置くのにかかる最短時間。ハードドロップは
//     瞬時にロックされるが、それでも移動・回転・出現待ちが必要になるため
//     150ms(=6.7個/秒)としており、これは人間の限界を大きく超える値。
//   - MAX_PIECE_SCORE_BASE: レベル1でのピースあたり最大得点の目安
//     (テトリス消し 800 + 大きめのコンボ加点 500 相当)。パーフェクトクリア
//     ボーナスは同じ盤面を毎ピース再現する必要があり現実的に連発できない
//     ため、この基準値には含めていない(その分の余裕は下の安全係数で吸収)。
//   - レベルは「1ピースにつき最大4ライン消去できた場合」という
//     最も好条件なケースで見積もる(実際にはまず不可能なペース)。
//   - 最後に安全係数と定額の許容分を加え、さらに大きく寛容にする。
const MIN_MS_PER_PIECE = 150;
const MAX_PIECE_SCORE_BASE = 1300;
const MARATHON_SAFETY_FACTOR = 3;
const MARATHON_FLAT_ALLOWANCE = 5000;

function maxPlausibleMarathonScore(tokenAgeMs){
  const pieces = Math.max(1, Math.floor(tokenAgeMs / MIN_MS_PER_PIECE));
  const level = Math.floor((pieces * 4) / 10) + 1;
  return pieces * MAX_PIECE_SCORE_BASE * level * MARATHON_SAFETY_FACTOR + MARATHON_FLAT_ALLOWANCE;
}

function corsHeaders(){
  return {
    'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}

function jsonResponse(body, status){
  return new Response(JSON.stringify(body), {
    status: status || 200,
    headers: { ...corsHeaders(), 'Content-Type': 'application/json' },
  });
}

async function getHmacKey(env){
  const keyData = new TextEncoder().encode(env.RANKING_SIGNING_KEY || '');
  return crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

function bufToHex(buf){
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBuf(hex){
  if(typeof hex !== 'string' || hex.length === 0 || hex.length % 2 !== 0) return null;
  const arr = new Uint8Array(hex.length / 2);
  for(let i = 0; i < arr.length; i++){
    const byte = parseInt(hex.substr(i * 2, 2), 16);
    if(Number.isNaN(byte)) return null;
    arr[i] = byte;
  }
  return arr;
}

async function issueToken(env){
  const key = await getHmacKey(env);
  const payload = btoa(JSON.stringify({ ts: Date.now() }));
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  return payload + '.' + bufToHex(sigBuf);
}

// Returns the token's issue timestamp (ms) if the signature is valid and
// well-formed, or null otherwise.
async function verifyToken(token, env){
  if(typeof token !== 'string') return null;
  const dot = token.indexOf('.');
  if(dot < 0) return null;
  const payload = token.slice(0, dot);
  const sigHex = token.slice(dot + 1);
  const sigBytes = hexToBuf(sigHex);
  if(!sigBytes) return null;
  const key = await getHmacKey(env);
  const valid = await crypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(payload));
  if(!valid) return null;
  try{
    const ts = JSON.parse(atob(payload)).ts;
    return Number.isFinite(ts) ? ts : null;
  }catch(e){
    return null;
  }
}

export default {
  async fetch(request, env){
    if(request.method === 'OPTIONS'){
      return new Response(null, { headers: corsHeaders() });
    }
    if(request.method !== 'POST'){
      return jsonResponse({ ok:false, error:'method not allowed' }, 405);
    }

    const url = new URL(request.url);
    if(url.pathname === '/start'){
      const token = await issueToken(env);
      return jsonResponse({ ok:true, token });
    }

    let data;
    try{
      data = await request.json();
    }catch(e){
      return jsonResponse({ ok:false, error:'invalid json' }, 400);
    }

    const mode = data.mode;
    const value = Number(data.value);
    let name = String(data.name || '').replace(/[\r\n]/g, '').trim().slice(0, 12);
    if(!name) name = '名無しさん';

    const validMode = mode === 'marathon' || mode === 'ta40';
    const validValue = Number.isFinite(value) && value >= 0 &&
      (mode === 'ta40' ? value <= 3600000 : value <= 99999999);

    if(!validMode || !validValue){
      return jsonResponse({ ok:false, error:'invalid submission' }, 400);
    }

    const tokenTs = await verifyToken(data.token, env);
    if(tokenTs === null){
      return jsonResponse({ ok:false, error:'missing or invalid start token' }, 400);
    }
    const tokenAge = Date.now() - tokenTs;
    if(tokenAge < 0 || tokenAge > TOKEN_MAX_AGE_MS){
      return jsonResponse({ ok:false, error:'start token expired' }, 400);
    }

    if(mode === 'ta40'){
      if(value < MIN_TA40_MS){
        return jsonResponse({ ok:false, error:'clear time below theoretical minimum' }, 400);
      }
      if(value > tokenAge + CLOCK_TOLERANCE_MS){
        return jsonResponse({ ok:false, error:'claimed time exceeds elapsed real time' }, 400);
      }
    } else {
      if(value > maxPlausibleMarathonScore(tokenAge)){
        return jsonResponse({ ok:false, error:'score implausible for elapsed time' }, 400);
      }
    }

    const body = 'mode: ' + mode + '\nvalue: ' + Math.round(value) + '\nname: ' + name;

    const ghRes = await fetch(
      `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/issues`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${env.GITHUB_TOKEN}`,
          'Accept': 'application/vnd.github+json',
          'User-Agent': 'ninniku-tetris-ranking-worker',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          title: 'ランキング登録: ' + name,
          body,
          labels: ['ranking'],
        }),
      }
    );

    if(!ghRes.ok){
      const detail = await ghRes.text();
      return jsonResponse({ ok:false, error:'github api error', detail: detail.slice(0, 300) }, 502);
    }

    const issue = await ghRes.json();
    return jsonResponse({ ok:true, issueNumber: issue.number });
  },
};

var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// worker.js
var ALLOWED_ORIGINS = [
  "https://scalo-business-os.vercel.app",
  "https://businessos.buildwithscalo.com",
  "https://portal.buildwithscalo.com",
  "https://timbrace14-dot.github.io"
];
var ADMIN_EMAILS = /* @__PURE__ */ new Set([
  "timbrace14@gmail.com"
]);
var PUBLIC_PATHS = /* @__PURE__ */ new Set([
  "/supabase-session",
  "/gcal/callback",
  "/stripe-webhook",
  "/waitlist-signup",
  "/kit-webhook",
  "/founding-count"
]);
async function requireSignedIn(request) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  if (!token) {
    const err = new Error("Missing Authorization: Bearer <firebase_id_token>");
    err.status = 401;
    throw err;
  }
  try {
    return await verifyFirebaseIdToken(token);
  } catch (e) {
    const err = new Error("Invalid auth token: " + e.message);
    err.status = 401;
    throw err;
  }
}
__name(requireSignedIn, "requireSignedIn");
async function requireAdmin(request) {
  const payload = await requireSignedIn(request);
  if (!payload.email || !ADMIN_EMAILS.has(payload.email)) {
    const err = new Error("Forbidden: admin access required");
    err.status = 403;
    throw err;
  }
  return payload;
}
__name(requireAdmin, "requireAdmin");
function buildCorsHeaders(request) {
  const origin = request.headers.get("Origin") || "";
  const allowOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Vary": "Origin"
  };
}
__name(buildCorsHeaders, "buildCorsHeaders");
var FIREBASE_PROJECT_ID = "scalo-client-portal";
var FIREBASE_JWKS_URL = "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";
var _firebaseKeysCache = null;
var CURRENT_COHORT = {
  name: "SCALO May 2026",
  start_date: "2026-05-18"
};
var PRICE_PIF = "price_1SZV04CYRZWN9CqHnZbmEl7E";
var PRICE_DEPOSIT = "price_1TP2ChCYRZWN9CqHD5KQV4Wz";
var PRICE_MONTHLY = "price_1TP2FBCYRZWN9CqH6KMZyD0d";
var PAYMENT_PLAN_SCHEDULE = [
  "2026-07-01",
  "2026-08-01",
  "2026-09-01",
  "2026-10-01",
  "2026-11-01",
  "2026-12-01"
];

// ─── FOUNDING-MEMBER COUNTER ───
var FOUNDING_TOTAL = 10;
var FOUNDING_COUNT_KEY = "founding_member_count";

var COHORT_SIGNUPS_PATH = "portal/cohort_signups";
var WAITLIST_PATH = "portal/waitlist";
function b64urlDecodeToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
__name(b64urlDecodeToBytes, "b64urlDecodeToBytes");
function b64urlDecodeToString(s) {
  return new TextDecoder().decode(b64urlDecodeToBytes(s));
}
__name(b64urlDecodeToString, "b64urlDecodeToString");
function b64urlEncodeBytes(bytes) {
  let bin = "";
  const u8 = new Uint8Array(bytes);
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
__name(b64urlEncodeBytes, "b64urlEncodeBytes");
function b64urlEncodeString(str) {
  return b64urlEncodeBytes(new TextEncoder().encode(str));
}
__name(b64urlEncodeString, "b64urlEncodeString");
async function getFirebasePublicKeys() {
  const now = Date.now();
  if (_firebaseKeysCache && _firebaseKeysCache.expiresAt > now) {
    return _firebaseKeysCache.keys;
  }
  const res = await fetch(FIREBASE_JWKS_URL);
  if (!res.ok) throw new Error("Failed to fetch Firebase JWKs: " + res.status);
  const { keys } = await res.json();
  const cc = res.headers.get("cache-control") || "";
  const m = cc.match(/max-age=(\d+)/);
  const maxAge = m ? parseInt(m[1], 10) : 3600;
  const keyMap = /* @__PURE__ */ new Map();
  for (const k of keys) keyMap.set(k.kid, k);
  _firebaseKeysCache = { keys: keyMap, expiresAt: now + maxAge * 1e3 };
  return keyMap;
}
__name(getFirebasePublicKeys, "getFirebasePublicKeys");
async function verifyFirebaseIdToken(idToken) {
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("Malformed token");
  const [headerB64, payloadB64, sigB64] = parts;
  const header = JSON.parse(b64urlDecodeToString(headerB64));
  const payload = JSON.parse(b64urlDecodeToString(payloadB64));
  const now = Math.floor(Date.now() / 1e3);
  if (!payload.exp || payload.exp < now) throw new Error("Token expired");
  if (payload.iat && payload.iat > now + 60) throw new Error("Token issued in future");
  if (payload.aud !== FIREBASE_PROJECT_ID) throw new Error("Wrong audience");
  if (payload.iss !== `https://securetoken.google.com/${FIREBASE_PROJECT_ID}`) throw new Error("Wrong issuer");
  if (!payload.sub) throw new Error("Missing sub");
  if (header.alg !== "RS256") throw new Error("Unexpected alg: " + header.alg);
  const keys = await getFirebasePublicKeys();
  const jwk = keys.get(header.kid);
  if (!jwk) throw new Error("Unknown signing key (kid=" + header.kid + ")");
  const pubKey = await crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const signed = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const sigBytes = b64urlDecodeToBytes(sigB64);
  const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", pubKey, sigBytes, signed);
  if (!valid) throw new Error("Invalid signature");
  return payload;
}
__name(verifyFirebaseIdToken, "verifyFirebaseIdToken");
async function signSupabaseJwt(claims, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const headerB64 = b64urlEncodeString(JSON.stringify(header));
  const payloadB64 = b64urlEncodeString(JSON.stringify(claims));
  const signingInput = `${headerB64}.${payloadB64}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signingInput));
  return `${signingInput}.${b64urlEncodeBytes(sig)}`;
}
__name(signSupabaseJwt, "signSupabaseJwt");
async function callClaude(env, systemPrompt, userMessage, maxRetries = 3) {
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": env.ANTHROPIC_KEY,
        "anthropic-version": "2023-06-01"
      },
      body: JSON.stringify({
        model: "claude-sonnet-4-20250514",
        max_tokens: 4096,
        messages: [{ role: "user", content: userMessage }],
        system: systemPrompt
      })
    });
    if (res.ok) {
      const data = await res.json();
      const text = (data.content || []).map((b) => b.text || "").join("");
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      if (jsonMatch) return JSON.parse(jsonMatch[0]);
      throw new Error("Could not parse AI response");
    }
    if (res.status === 529 || res.status === 503 || res.status === 429) {
      if (attempt < maxRetries - 1) {
        await new Promise((r) => setTimeout(r, (attempt + 1) * 2e3));
        continue;
      }
    }
    const errText = await res.text();
    throw new Error("Claude API " + res.status + ": " + errText.slice(0, 300));
  }
}
__name(callClaude, "callClaude");
function detectPlatform(url) {
  if (/instagram\.com\/(reel|p)\//i.test(url)) return "instagram";
  if (/youtube\.com\/watch|youtu\.be\/|youtube\.com\/shorts\//i.test(url)) return "youtube";
  return null;
}
__name(detectPlatform, "detectPlatform");
function extractYtVideoId(url) {
  const m = url.match(/(?:v=|youtu\.be\/|shorts\/)([a-zA-Z0-9_-]{11})/);
  return m ? m[1] : null;
}
__name(extractYtVideoId, "extractYtVideoId");
async function fetchYouTubeTranscript(videoId, apifyToken) {
  let title = "", views = 0, description = "";
  try {
    const oembedRes = await fetch(`https://www.youtube.com/oembed?url=https://www.youtube.com/watch?v=${videoId}&format=json`);
    if (oembedRes.ok) {
      const oembed = await oembedRes.json();
      title = oembed.title || "";
    }
  } catch {}
  let transcript = null;
  if (apifyToken) {
    try {
      const items = await runApifyActor("karamelo~youtube-transcripts", apifyToken, {
        urls: [`https://www.youtube.com/watch?v=${videoId}`]
      });
      const item = (items || [])[0];
      if (item) {
        if (item.transcript) transcript = item.transcript;
        else if (item.text) transcript = item.text;
        else if (Array.isArray(item.captions)) {
          transcript = item.captions.map((c) => c.text || c).filter(Boolean).join(" ");
        } else if (item.content) transcript = item.content;
        if (!title && item.title) title = item.title;
      }
    } catch {}
  }
  if (!transcript && apifyToken) {
    try {
      const items = await runApifyActor("akash9078~youtube-transcript-extractor", apifyToken, {
        videoUrls: [`https://www.youtube.com/watch?v=${videoId}`]
      });
      const item = (items || [])[0];
      if (item) {
        if (item.transcript) transcript = item.transcript;
        else if (item.text) transcript = item.text;
        else if (Array.isArray(item.captions)) {
          transcript = item.captions.map((c) => c.text || c).filter(Boolean).join(" ");
        }
        if (!title && item.title) title = item.title;
      }
    } catch {}
  }
  return { title, transcript, description, views };
}
__name(fetchYouTubeTranscript, "fetchYouTubeTranscript");
async function transcribeVideoAudio(env, videoUrl) {
  if (!env.AI) return null;
  try {
    const videoRes = await fetch(videoUrl, {
      headers: { "User-Agent": "Mozilla/5.0" }
    });
    if (!videoRes.ok) return null;
    const audioBuffer = await videoRes.arrayBuffer();
    const result = await env.AI.run("@cf/openai/whisper", {
      audio: [...new Uint8Array(audioBuffer)]
    });
    return result && result.text ? result.text : null;
  } catch (e) {
    console.log("Whisper transcription error:", e.message);
    return null;
  }
}
__name(transcribeVideoAudio, "transcribeVideoAudio");
async function fetchInstagramPost(url, apifyToken) {
  const items = await runApifyActor("apify~instagram-scraper", apifyToken, {
    directUrls: [url],
    resultsType: "posts",
    resultsLimit: 1,
    addParentData: false
  });
  const p = (items || [])[0];
  if (!p) throw new Error("Could not fetch Instagram post — check the URL is a public reel");
  return {
    title: (p.caption || "").slice(0, 100),
    caption: p.caption || "",
    views: p.videoPlayCount || p.videoViewCount || p.playsCount || 0,
    likes: p.likesCount || 0,
    thumbnail: p.displayUrl || "",
    ownerUsername: p.ownerUsername || "",
    videoUrl: p.videoUrl || ""
  };
}
__name(fetchInstagramPost, "fetchInstagramPost");
function extractIgHandle(input) {
  if (!input) return null;
  const m = input.match(/instagram\.com\/([^\/?#]+)/i);
  if (m) return m[1].replace("@", "");
  return input.replace(/^@/, "").trim();
}
__name(extractIgHandle, "extractIgHandle");
function extractYtChannel(input) {
  if (!input) return null;
  const m = input.match(/youtube\.com\/(@[^\/?#]+|channel\/[^\/?#]+|c\/[^\/?#]+|user\/[^\/?#]+)/i);
  if (m) return m[1];
  return input.replace(/^@/, "");
}
__name(extractYtChannel, "extractYtChannel");
async function runApifyActor(actorId, token, input) {
  const res = await fetch(`https://api.apify.com/v2/acts/${actorId}/run-sync-get-dataset-items?token=${token}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input)
  });
  if (!res.ok) throw new Error("Apify " + res.status + ": " + (await res.text()).slice(0, 200));
  return res.json();
}
__name(runApifyActor, "runApifyActor");
async function scrapeIgTopReels(handleOrUrl, token, days) {
  const handle = extractIgHandle(handleOrUrl);
  if (!handle) throw new Error("Invalid Instagram handle");
  const items = await runApifyActor("apify~instagram-scraper", token, {
    directUrls: [`https://www.instagram.com/${handle}/reels/`],
    resultsType: "posts",
    resultsLimit: 30,
    addParentData: false
  });
  const sinceMs = days ? Date.now() - days * 864e5 : 0;
  return (items || []).filter((p) => (p.type === "Video" || p.productType === "clips") && (!sinceMs || new Date(p.timestamp).getTime() >= sinceMs)).map((p) => ({
    title: (p.caption || "").slice(0, 80) || "Reel",
    views: p.videoPlayCount || p.videoViewCount || p.playsCount || 0,
    likes: p.likesCount || 0,
    url: p.url || `https://www.instagram.com/p/${p.shortCode}/`,
    thumbnail: p.displayUrl || "",
    posted: p.timestamp || ""
  })).sort((a, b) => b.views - a.views).slice(0, 3);
}
__name(scrapeIgTopReels, "scrapeIgTopReels");
async function scrapeYtTopVideos(channelOrUrl, token, days) {
  const ch = extractYtChannel(channelOrUrl);
  if (!ch) throw new Error("Invalid YouTube channel");
  const startUrl = ch.startsWith("@") || ch.startsWith("channel/") || ch.startsWith("c/") || ch.startsWith("user/") ? `https://www.youtube.com/${ch}/videos` : `https://www.youtube.com/@${ch}/videos`;
  const items = await runApifyActor("streamers~youtube-scraper", token, {
    startUrls: [{ url: startUrl }],
    maxResults: 30,
    maxResultsShorts: 0,
    maxResultStreams: 0
  });
  const sinceMs = days ? Date.now() - days * 864e5 : 0;
  return (items || []).filter((v) => !sinceMs || v.date && new Date(v.date).getTime() >= sinceMs).map((v) => ({
    title: v.title || "Video",
    views: v.viewCount || 0,
    likes: v.likes || 0,
    url: v.url || `https://www.youtube.com/watch?v=${v.id}`,
    thumbnail: v.thumbnailUrl || "",
    posted: v.date || ""
  })).sort((a, b) => b.views - a.views).slice(0, 3);
}
__name(scrapeYtTopVideos, "scrapeYtTopVideos");
async function scrapeIgProfile(handleOrUrl, token) {
  const handle = extractIgHandle(handleOrUrl);
  if (!handle) throw new Error("Invalid Instagram handle");
  const items = await runApifyActor("apify~instagram-profile-scraper", token, {
    usernames: [handle]
  });
  const p = (items || [])[0] || {};
  let viewsSum = 0;
  if (Array.isArray(p.latestPosts)) {
    p.latestPosts.forEach((post) => {
      viewsSum += post.videoPlayCount || post.videoViewCount || post.playsCount || 0;
    });
  }
  return {
    followers: p.followersCount || 0,
    following: p.followsCount || 0,
    posts: p.postsCount || 0,
    views: viewsSum,
    handle
  };
}
__name(scrapeIgProfile, "scrapeIgProfile");
async function scrapeYtChannel(channelOrUrl, token) {
  const ch = extractYtChannel(channelOrUrl);
  if (!ch) throw new Error("Invalid YouTube channel");
  const startUrl = ch.startsWith("@") || ch.startsWith("channel/") || ch.startsWith("c/") || ch.startsWith("user/") ? `https://www.youtube.com/${ch}` : `https://www.youtube.com/@${ch}`;
  const items = await runApifyActor("streamers~youtube-scraper", token, {
    startUrls: [{ url: startUrl }],
    maxResults: 1,
    maxResultsShorts: 0,
    maxResultStreams: 0
  });
  const v = (items || [])[0] || {};
  return {
    subs: v.numberOfSubscribers || v.channelTotalSubscribers || 0,
    views: v.channelTotalViews || 0,
    videos: v.channelTotalVideos || 0,
    channel: ch
  };
}
__name(scrapeYtChannel, "scrapeYtChannel");
async function stripe(path, key) {
  const res = await fetch("https://api.stripe.com/v1" + path, {
    headers: { Authorization: "Bearer " + key }
  });
  if (!res.ok) throw new Error("Stripe " + res.status + " " + await res.text());
  return res.json();
}
__name(stripe, "stripe");
function monthStartUnix(offset = 0) {
  const d = /* @__PURE__ */ new Date();
  d.setUTCDate(1);
  d.setUTCHours(0, 0, 0, 0);
  d.setUTCMonth(d.getUTCMonth() + offset);
  return Math.floor(d.getTime() / 1e3);
}
__name(monthStartUnix, "monthStartUnix");
async function getStats(key) {
  const thisStart = monthStartUnix(0);
  const prevStart = monthStartUnix(-1);
  const now = Math.floor(Date.now() / 1e3);
  const charges = [];
  let hasMore = true, startingAfter = null;
  while (hasMore) {
    const q = `/charges?limit=100${startingAfter ? "&starting_after=" + startingAfter : ""}`;
    const page = await stripe(q, key);
    charges.push(...page.data.filter((c) => c.paid && !c.refunded));
    hasMore = page.has_more;
    if (hasMore) startingAfter = page.data[page.data.length - 1].id;
    if (charges.length > 5e3) break;
  }
  const earliestTs = charges.reduce((min, c) => Math.min(min, c.created), Math.floor(Date.now() / 1e3));
  const earliestDate = new Date(earliestTs * 1e3);
  const today = /* @__PURE__ */ new Date();
  const monthsSpan = (today.getUTCFullYear() - earliestDate.getUTCFullYear()) * 12 + (today.getUTCMonth() - earliestDate.getUTCMonth()) + 1;
  const buckets = {};
  const labels = [];
  for (let i = -(monthsSpan - 1); i <= 0; i++) {
    const d = /* @__PURE__ */ new Date();
    d.setUTCDate(1);
    d.setUTCMonth(d.getUTCMonth() + i);
    const lbl = d.toLocaleString("en-GB", { month: "short", year: "2-digit" });
    buckets[lbl] = 0;
    labels.push(lbl);
  }
  let mtdRevenue = 0, mtdRevenuePrev = 0;
  charges.forEach((c) => {
    const amt = (c.amount_captured || c.amount) / 100;
    const d = new Date(c.created * 1e3);
    const lbl = d.toLocaleString("en-GB", { month: "short", year: "2-digit" });
    if (buckets[lbl] !== void 0) buckets[lbl] += amt;
    if (c.created >= thisStart && c.created < now) mtdRevenue += amt;
    if (c.created >= prevStart && c.created < thisStart) mtdRevenuePrev += amt;
  });
  const customersMTD = await stripe(`/customers?limit=100&created[gte]=${thisStart}`, key);
  const customersPrev = await stripe(`/customers?limit=100&created[gte]=${prevStart}&created[lt]=${thisStart}`, key);
  const subs = await stripe("/subscriptions?status=active&limit=100", key);
  let mrr = 0;
  subs.data.forEach((s) => {
    if (s.cancel_at_period_end && s.status !== "active") return;
    s.items.data.forEach((item) => {
      const price = item.price;
      if (!price || !price.unit_amount || !price.recurring) return;
      const monthsPerInterval = {
        day: 1 / 30.4375,
        week: 12 / 52,
        month: 1,
        year: 12
      }[price.recurring.interval] || 1;
      const count = price.recurring.interval_count || 1;
      const monthly = price.unit_amount / (monthsPerInterval * count);
      mrr += monthly * (item.quantity || 1) / 100;
    });
  });
  const recent = customersMTD.data.slice(0, 10).map((c) => ({
    date: new Date(c.created * 1e3).toISOString().slice(0, 10),
    name: c.name || c.email || "Customer",
    email: c.email || "",
    plan: "SCALO",
    amount: 0
  }));
  const dayMs = 864e5;
  const todayMid = /* @__PURE__ */ new Date();
  todayMid.setUTCHours(0, 0, 0, 0);
  const dayBuckets = [];
  for (let i = 29; i >= 0; i--) {
    const d = new Date(todayMid.getTime() - i * dayMs);
    dayBuckets.push({ key: d.toISOString().slice(0, 10), label: d.toLocaleString("en-GB", { day: "numeric", month: "short" }), value: 0 });
  }
  const dayIdx = {};
  dayBuckets.forEach((b, i) => dayIdx[b.key] = i);
  let grossVolume = 0;
  charges.forEach((c) => {
    const amt = (c.amount_captured || c.amount) / 100;
    grossVolume += amt;
    const k = new Date(c.created * 1e3).toISOString().slice(0, 10);
    if (dayIdx[k] !== void 0) dayBuckets[dayIdx[k]].value += amt;
  });
  return {
    grossVolume: Math.round(grossVolume),
    thisMonth: Math.round(mtdRevenue),
    series: dayBuckets.map((d) => ({ label: d.label, value: Math.round(d.value) })),
    mtdRevenue: Math.round(mtdRevenue),
    mtdRevenuePrev: Math.round(mtdRevenuePrev),
    newCustomersMTD: customersMTD.data.length,
    newCustomersPrev: customersPrev.data.length,
    activeSubscriptions: subs.data.length,
    mrr: Math.round(mrr),
    mrrPrev: Math.round(mrr * 0.92),
    revenueByMonth: labels.map((l) => ({ label: l, value: Math.round(buckets[l]) })),
    recentCustomers: recent
  };
}
__name(getStats, "getStats");
async function getRevenueSeries(key, days) {
  days = Math.min(Math.max(parseInt(days, 10) || 30, 1), 365);
  const charges = [];
  let hasMore = true, startingAfter = null;
  const sinceTs = Math.floor((Date.now() - days * 864e5) / 1e3);
  while (hasMore) {
    const q = `/charges?limit=100&created[gte]=${sinceTs}${startingAfter ? "&starting_after=" + startingAfter : ""}`;
    const page = await stripe(q, key);
    charges.push(...page.data.filter((c) => c.paid && !c.refunded));
    hasMore = page.has_more;
    if (hasMore && page.data.length) startingAfter = page.data[page.data.length - 1].id;
    if (charges.length > 5e3) break;
  }
  const todayMid = /* @__PURE__ */ new Date();
  todayMid.setUTCHours(0, 0, 0, 0);
  const buckets = [];
  const idx = {};
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(todayMid.getTime() - i * 864e5);
    const k = d.toISOString().slice(0, 10);
    const b = { key: k, label: d.toLocaleString("en-GB", { day: "numeric", month: "short" }), value: 0 };
    idx[k] = buckets.length;
    buckets.push(b);
  }
  let total = 0;
  charges.forEach((c) => {
    const amt = (c.amount_captured || c.amount) / 100;
    total += amt;
    const k = new Date(c.created * 1e3).toISOString().slice(0, 10);
    if (idx[k] !== void 0) buckets[idx[k]].value += amt;
  });
  const subs = await stripe("/subscriptions?status=active&limit=100", key);
  let mrr = 0;
  subs.data.forEach((s) => {
    if (s.cancel_at_period_end && s.status !== "active") return;
    s.items.data.forEach((item) => {
      const price = item.price;
      if (!price || !price.unit_amount || !price.recurring) return;
      const monthsPerInterval = {
        day: 1 / 30.4375,
        week: 12 / 52,
        month: 1,
        year: 12
      }[price.recurring.interval] || 1;
      const count = price.recurring.interval_count || 1;
      const monthly = price.unit_amount / (monthsPerInterval * count);
      mrr += monthly * (item.quantity || 1) / 100;
    });
  });
  return {
    days,
    total: Math.round(total),
    mrr: Math.round(mrr),
    series: buckets.map((b) => ({ label: b.label, value: Math.round(b.value) }))
  };
}
__name(getRevenueSeries, "getRevenueSeries");
async function runDailyScrape(env) {
  if (!env.APIFY_TOKEN || !env.SCALO_STATS) return;
  const today = (/* @__PURE__ */ new Date()).toISOString().slice(0, 10);
  const ts = Date.now();
  const append = /* @__PURE__ */ __name(async (account, snap) => {
    const key = "history:" + account;
    const arr = await env.SCALO_STATS.get(key, { type: "json" }) || [];
    const idx = arr.findIndex((e) => e.date === today);
    const entry = { date: today, ts, ...snap };
    if (idx >= 0) arr[idx] = entry;
    else arr.push(entry);
    if (arr.length > 365) arr.splice(0, arr.length - 365);
    await env.SCALO_STATS.put(key, JSON.stringify(arr));
  }, "append");
  try {
    const [ig, yt] = await Promise.all([
      env.SCALO_IG ? scrapeIgProfile(env.SCALO_IG, env.APIFY_TOKEN) : null,
      env.SCALO_YT ? scrapeYtChannel(env.SCALO_YT, env.APIFY_TOKEN) : null
    ]);
    if (ig || yt) {
      await append("scalo_with_tim", {
        igViews: ig?.views || 0,
        igFollowers: ig?.followers || 0,
        ytViews: yt?.views || 0,
        ytSubs: yt?.subs || 0
      });
    }
  } catch (e) {
    console.log("SCALO scrape failed", e.message);
  }
  try {
    if (env.TBH_IG) {
      const ig = await scrapeIgProfile(env.TBH_IG, env.APIFY_TOKEN);
      if (ig) {
        const eng = ig.followers && ig.views ? Math.min(ig.views / 30 / ig.followers * 100, 25) : 0;
        await append("tim_brace_hair", {
          igViews: ig.views || 0,
          igFollowers: ig.followers || 0,
          igEng: Math.round(eng * 10) / 10,
          igVisits: Math.round((ig.followers || 0) * 0.18)
        });
      }
    }
  } catch (e) {
    console.log("TBH scrape failed", e.message);
  }
}
__name(runDailyScrape, "runDailyScrape");
async function pingSupabase(env) {
  try {
    const url = env.SUPABASE_URL || "https://kadgzthwuzzjwxxcbgzi.supabase.co";
    const key = env.SUPABASE_ANON_KEY || "";
    if (!key) {
      console.log("Supabase keepalive: no anon key configured");
      return;
    }
    const res = await fetch(`${url}/rest/v1/?apikey=${key}`, {
      headers: { "Authorization": `Bearer ${key}`, "Content-Type": "application/json" }
    });
    console.log("Supabase keepalive ping:", res.status);
  } catch (e) {
    console.log("Supabase keepalive failed:", e.message);
  }
}
__name(pingSupabase, "pingSupabase");
async function verifyStripeSignature(payload, sigHeader, secret) {
  if (!sigHeader) throw new Error("Missing Stripe-Signature header");
  const parts = {};
  sigHeader.split(",").forEach((p) => {
    const [k, v] = p.split("=");
    if (!parts[k]) parts[k] = v;
    else if (k === "v1") parts[k] = (Array.isArray(parts[k]) ? parts[k] : [parts[k]]).concat(v);
  });
  const timestamp = parts.t;
  const v1 = parts.v1;
  if (!timestamp || !v1) throw new Error("Malformed signature header");
  const ageSec = Math.abs(Math.floor(Date.now() / 1e3) - parseInt(timestamp, 10));
  if (ageSec > 300) throw new Error("Signature timestamp too old");
  const signedPayload = `${timestamp}.${payload}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sigBytes = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signedPayload));
  const expected = Array.from(new Uint8Array(sigBytes)).map((b) => b.toString(16).padStart(2, "0")).join("");
  const candidates = Array.isArray(v1) ? v1 : [v1];
  if (!candidates.includes(expected)) throw new Error("Signature mismatch");
}
__name(verifyStripeSignature, "verifyStripeSignature");
var _firebaseAccessTokenCache = null;
async function getFirebaseAccessToken(env) {
  if (!env.FIREBASE_SERVICE_ACCOUNT) throw new Error("FIREBASE_SERVICE_ACCOUNT not configured");
  const now = Date.now();
  if (_firebaseAccessTokenCache && _firebaseAccessTokenCache.expiresAt > now + 6e4) {
    return _firebaseAccessTokenCache.token;
  }
  const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
  const iat = Math.floor(now / 1e3);
  const claims = {
    iss: sa.client_email,
    scope: "https://www.googleapis.com/auth/firebase.database https://www.googleapis.com/auth/userinfo.email",
    aud: "https://oauth2.googleapis.com/token",
    iat,
    exp: iat + 3600
  };
  const headerB64 = b64urlEncodeString(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claimsB64 = b64urlEncodeString(JSON.stringify(claims));
  const signingInput = `${headerB64}.${claimsB64}`;
  const pemBody = sa.private_key.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").replace(/\s+/g, "");
  const pkcs8 = Uint8Array.from(atob(pemBody), (c) => c.charCodeAt(0));
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sigBytes = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, new TextEncoder().encode(signingInput));
  const jwt = `${signingInput}.${b64urlEncodeBytes(sigBytes)}`;
  const tokRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt
    })
  });
  if (!tokRes.ok) throw new Error("Google token exchange failed: " + (await tokRes.text()).slice(0, 300));
  const data = await tokRes.json();
  _firebaseAccessTokenCache = {
    token: data.access_token,
    expiresAt: now + (data.expires_in - 60) * 1e3
  };
  return data.access_token;
}
__name(getFirebaseAccessToken, "getFirebaseAccessToken");
function rtdbUrl(env, path) {
  const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
  return `https://${sa.project_id}-default-rtdb.firebaseio.com/${path}.json`;
}
__name(rtdbUrl, "rtdbUrl");
async function rtdbWrite(env, path, data) {
  const token = await getFirebaseAccessToken(env);
  const res = await fetch(rtdbUrl(env, path), {
    method: "PUT",
    headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
    body: JSON.stringify(data)
  });
  if (!res.ok) throw new Error("RTDB PUT failed: " + res.status + " " + (await res.text()).slice(0, 200));
  return res.json();
}
__name(rtdbWrite, "rtdbWrite");
async function rtdbUpdate(env, path, updates) {
  const token = await getFirebaseAccessToken(env);
  const res = await fetch(rtdbUrl(env, path), {
    method: "PATCH",
    headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
    body: JSON.stringify(updates)
  });
  if (!res.ok) throw new Error("RTDB PATCH failed: " + res.status + " " + (await res.text()).slice(0, 200));
  return res.json();
}
__name(rtdbUpdate, "rtdbUpdate");
async function rtdbRead(env, path) {
  const token = await getFirebaseAccessToken(env);
  const res = await fetch(rtdbUrl(env, path), {
    headers: { Authorization: "Bearer " + token }
  });
  if (!res.ok) throw new Error("RTDB GET failed: " + res.status + " " + (await res.text()).slice(0, 200));
  return res.json();
}
__name(rtdbRead, "rtdbRead");
async function findSignupBySubscription(env, subscriptionId) {
  if (!subscriptionId) return null;
  const all = await rtdbRead(env, COHORT_SIGNUPS_PATH) || {};
  for (const [id, rec] of Object.entries(all)) {
    if (rec && rec.stripe_subscription_id === subscriptionId) return { id, record: rec };
  }
  return null;
}
__name(findSignupBySubscription, "findSignupBySubscription");
function rtdbSafeKey(s) {
  return String(s || "").replace(/[.#$\[\]\/]/g, "_");
}
__name(rtdbSafeKey, "rtdbSafeKey");
async function handleWaitlistSignup(request, env, corsHeaders) {
  corsHeaders = {
    ...corsHeaders,
    "Access-Control-Allow-Origin": "*",
    "Vary": "Origin"
  };
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }
  if (request.method !== "POST") {
    return new Response(JSON.stringify({ error: "POST required" }), {
      status: 405,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonErr("Invalid JSON", 400, corsHeaders);
  }
  const email = String(body.email || "").trim().toLowerCase();
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return jsonErr("Valid email required", 400, corsHeaders);
  }
  if (email.length > 200) return jsonErr("Email too long", 400, corsHeaders);
  const clip = /* @__PURE__ */ __name((s, n) => String(s || "").trim().slice(0, n), "clip");
  const firstName = clip(body.first_name, 80);
  const lastName = clip(body.last_name, 80);
  const fullName = clip(body.name || [firstName, lastName].filter(Boolean).join(" "), 160);
  const phone = clip(body.phone, 30);
  const instagram = clip(body.instagram, 60).replace(/^@/, "");
  const source = clip(body.source || body.utm_source, 60) || "landing_page";
  const medium = clip(body.utm_medium, 60);
  const campaign = clip(body.utm_campaign, 80);
  const cohort = clip(body.cohort, 80) || CURRENT_COHORT.name;
  const key = rtdbSafeKey(email);
  const now = (/* @__PURE__ */ new Date()).toISOString();
  let existing = null;
  try {
    existing = await rtdbRead(env, `${WAITLIST_PATH}/${key}`);
  } catch {}
  const record = {
    email,
    name: fullName || existing && existing.name || "",
    first_name: firstName || existing && existing.first_name || "",
    last_name: lastName || existing && existing.last_name || "",
    phone: phone || existing && existing.phone || "",
    instagram: instagram || existing && existing.instagram || "",
    source,
    utm_medium: medium || null,
    utm_campaign: campaign || null,
    cohort,
    signup_timestamp: existing && existing.signup_timestamp ? existing.signup_timestamp : now,
    last_seen: now,
    nurture_status: existing && existing.nurture_status ? existing.nurture_status : "new",
    notes: existing && existing.notes ? existing.notes : ""
  };
  await rtdbWrite(env, `${WAITLIST_PATH}/${key}`, record);
  try {
    await pushWaitlistFeedEvent(env, record);
  } catch (e) {
    console.log("Waitlist feed push failed (non-fatal):", e.message);
  }
  return new Response(JSON.stringify({ ok: true, email }), {
    headers: { ...corsHeaders, "Content-Type": "application/json" }
  });
}
__name(handleWaitlistSignup, "handleWaitlistSignup");
function jsonErr(message, status, corsHeaders) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" }
  });
}
__name(jsonErr, "jsonErr");

// ─── FOUNDING-MEMBER COUNTER (NEW) ───
// Public read endpoint for the SCALO sales page. Returns { count, total }.
async function handleFoundingCount(request, env, corsHeaders) {
  const headers = {
    ...corsHeaders,
    "Access-Control-Allow-Origin": "*",
    "Vary": "Origin",
    "Content-Type": "application/json",
    "Cache-Control": "no-store"
  };
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers });
  }
  if (request.method !== "GET") {
    return new Response("Method not allowed", { status: 405, headers });
  }
  let count = 0;
  if (env.SCALO_STATS) {
    const raw = await env.SCALO_STATS.get(FOUNDING_COUNT_KEY);
    count = parseInt(raw || "0", 10) || 0;
  }
  return new Response(JSON.stringify({ count, total: FOUNDING_TOTAL, updatedAt: Date.now() }), { headers });
}
__name(handleFoundingCount, "handleFoundingCount");

async function handleKitWebhook(request, env, corsHeaders) {
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }
  if (request.method !== "POST") {
    return jsonErr("POST required", 405, corsHeaders);
  }
  const expected = env.KIT_WEBHOOK_TOKEN;
  if (!expected) return jsonErr("KIT_WEBHOOK_TOKEN not configured", 500, corsHeaders);
  const url = new URL(request.url);
  const provided = url.searchParams.get("token") || "";
  if (provided !== expected) return jsonErr("Invalid token", 401, corsHeaders);
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonErr("Invalid JSON", 400, corsHeaders);
  }
  const sub = body.subscriber || body;
  const email = String(sub.email_address || sub.email || "").trim().toLowerCase();
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return jsonErr("Subscriber missing valid email_address", 400, corsHeaders);
  }
  const clip = /* @__PURE__ */ __name((s, n) => String(s || "").trim().slice(0, n), "clip");
  const fields = sub.fields || {};
  const fullName = [sub.first_name, fields.last_name].filter(Boolean).join(" ").trim();
  const name = clip(fullName || sub.name, 120);
  const tags = Array.isArray(sub.tags) ? sub.tags.map((t) => t && t.name || t || "").filter(Boolean) : [];
  const utmTag = tags.find((t) => /^utm[:_-]/i.test(t));
  const source = clip(utmTag ? utmTag.replace(/^utm[:_-]/i, "") : fields.utm_source || "kit", 60);
  const medium = clip(fields.utm_medium, 60);
  const key = rtdbSafeKey(email);
  const now = (/* @__PURE__ */ new Date()).toISOString();
  let existing = null;
  try {
    existing = await rtdbRead(env, `${WAITLIST_PATH}/${key}`);
  } catch {}
  const record = {
    email,
    name: name || existing && existing.name || "",
    source,
    utm_medium: medium || null,
    cohort: clip(fields.cohort, 80) || CURRENT_COHORT.name,
    signup_timestamp: existing && existing.signup_timestamp ? existing.signup_timestamp : sub.created_at || now,
    last_seen: now,
    nurture_status: existing && existing.nurture_status ? existing.nurture_status : "new",
    notes: existing && existing.notes ? existing.notes : "",
    kit_subscriber_id: sub.id || null,
    kit_tags: tags
  };
  await rtdbWrite(env, `${WAITLIST_PATH}/${key}`, record);
  try {
    await pushWaitlistFeedEvent(env, record);
  } catch (e) {
    console.log("Kit webhook feed push failed (non-fatal):", e.message);
  }
  return new Response(JSON.stringify({ ok: true, email, source: record.source }), {
    headers: { ...corsHeaders, "Content-Type": "application/json" }
  });
}
__name(handleKitWebhook, "handleKitWebhook");
async function handleStripeWebhook(request, env, corsHeaders) {
  if (request.method !== "POST") {
    return new Response("Method not allowed", { status: 405, headers: corsHeaders });
  }
  const secrets = [env.STRIPE_WEBHOOK_SECRET, env.STRIPE_WEBHOOK_SECRET_TEST].filter(Boolean);
  if (!secrets.length) {
    return new Response(JSON.stringify({ error: "STRIPE_WEBHOOK_SECRET not configured" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
  const payload = await request.text();
  const sig = request.headers.get("Stripe-Signature") || "";
  let verified = false;
  let lastErr;
  for (const secret of secrets) {
    try {
      await verifyStripeSignature(payload, sig, secret);
      verified = true;
      break;
    } catch (e) {
      lastErr = e;
    }
  }
  if (!verified) {
    return new Response(JSON.stringify({ error: "Signature verification failed: " + (lastErr?.message || "unknown") }), {
      status: 400,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
  let event;
  try {
    event = JSON.parse(payload);
  } catch {
    return new Response(JSON.stringify({ error: "Invalid JSON payload" }), {
      status: 400,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
  try {
    switch (event.type) {
      case "checkout.session.completed":
        await handleCheckoutCompleted(event, env);
        break;
      case "invoice.paid":
        await handleInvoicePaid(event, env);
        break;
      case "invoice.payment_failed":
        await handleInvoiceFailed(event, env);
        break;
      case "customer.subscription.deleted":
        await handleSubscriptionDeleted(event, env);
        break;
      default:
        break;
    }
    return new Response(JSON.stringify({ received: true, type: event.type }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  } catch (e) {
    console.log("Stripe webhook handler error:", event.type, e.message);
    return new Response(JSON.stringify({ error: e.message, type: event.type }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
}
__name(handleStripeWebhook, "handleStripeWebhook");
async function classifyCheckoutSession(sessionId, stripeKey) {
  const full = await stripe(`/checkout/sessions/${sessionId}?expand[]=line_items`, stripeKey);
  const prices = (full.line_items?.data || []).map((i) => i.price?.id).filter(Boolean);
  let type = "Unknown";
  if (prices.includes(PRICE_PIF)) type = "PIF";
  else if (prices.includes(PRICE_DEPOSIT) || prices.includes(PRICE_MONTHLY)) type = "Payment Plan";
  return { type, session: full };
}
__name(classifyCheckoutSession, "classifyCheckoutSession");
async function handleCheckoutCompleted(event, env) {
  const short = event.data.object;

  // ─── Founding-member counter (10-spot limit on £499 link) ───
  // Fires for every checkout.session.completed; only increments when the
  // session was created via the founding payment link.
  if (env.FOUNDING_PAYMENT_LINK_ID && env.SCALO_STATS && short.payment_link === env.FOUNDING_PAYMENT_LINK_ID) {
    try {
      const raw = await env.SCALO_STATS.get(FOUNDING_COUNT_KEY);
      const current = parseInt(raw || "0", 10) || 0;
      const next = Math.min(FOUNDING_TOTAL, current + 1);
      await env.SCALO_STATS.put(FOUNDING_COUNT_KEY, String(next));
    } catch (e) {
      console.log("Founding counter update failed:", e.message);
    }
  }

  // ─── Existing cohort signup logic (unchanged) ───
  const { type, session } = await classifyCheckoutSession(short.id, env.STRIPE_KEY);
  if (type === "Unknown") {
    console.log("checkout.session.completed with unknown price mix — skipping:", short.id);
    return;
  }
  const details = session.customer_details || {};
  const meta = session.metadata || {};
  const isPif = type === "PIF";
  const record = {
    email: details.email || "",
    name: details.name || "",
    phone: details.phone || "",
    cohort: meta.cohort || CURRENT_COHORT.name,
    cohort_start_date: meta.cohort_start_date || CURRENT_COHORT.start_date,
    signup_timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    payment_type: type,
    total_value: isPif ? 3e3 : 4500,
    amount_paid_to_date: isPif ? 3e3 : 1500,
    payments_completed: 1,
    total_payments: isPif ? 1 : 7,
    next_payment_date: isPif ? null : PAYMENT_PLAN_SCHEDULE[0],
    next_payment_amount: isPif ? 0 : 500,
    payment_status: isPif ? "Paid in full" : "Payment 1 of 7 complete",
    stripe_customer_id: session.customer || "",
    stripe_subscription_id: session.subscription || null,
    onboarding_status: "new",
    onboarded_at: null,
    notes: "",
    payment_failed_at: null,
    subscription_ended_at: null
  };
  const key = rtdbSafeKey(session.customer || session.id);
  await rtdbWrite(env, `${COHORT_SIGNUPS_PATH}/${key}`, record);
  await pushCohortFeedEvent(env, {
    kind: "signup",
    title: `New ${type} signup: ${record.name || record.email}`,
    cohort: record.cohort,
    amount: record.amount_paid_to_date,
    email: record.email,
    name: record.name
  });
}
__name(handleCheckoutCompleted, "handleCheckoutCompleted");
async function handleInvoicePaid(event, env) {
  const invoice = event.data.object;
  if (invoice.billing_reason === "subscription_create") return;
  if (!invoice.subscription) return;
  const found = await findSignupBySubscription(env, invoice.subscription);
  if (!found) {
    console.log("invoice.paid: no matching signup for subscription", invoice.subscription);
    return;
  }
  const amountPaid = (invoice.amount_paid || 0) / 100;
  const newCompleted = (found.record.payments_completed || 0) + 1;
  const totalPayments = found.record.total_payments || 7;
  const isFinal = newCompleted >= totalPayments;
  const nextDate = isFinal ? null : PAYMENT_PLAN_SCHEDULE[newCompleted - 1] || null;
  const updates = {
    payments_completed: newCompleted,
    amount_paid_to_date: (found.record.amount_paid_to_date || 0) + amountPaid,
    next_payment_date: nextDate,
    next_payment_amount: isFinal ? 0 : 500,
    payment_status: isFinal ? "All payments complete" : `Payment ${newCompleted} of ${totalPayments} complete`,
    payment_failed_at: null
  };
  await rtdbUpdate(env, `${COHORT_SIGNUPS_PATH}/${found.id}`, updates);
  await pushCohortFeedEvent(env, {
    kind: "payment",
    title: `${found.record.name || found.record.email}: payment ${newCompleted} of ${totalPayments} received`,
    cohort: found.record.cohort,
    amount: amountPaid,
    email: found.record.email,
    name: found.record.name
  });
}
__name(handleInvoicePaid, "handleInvoicePaid");
async function handleInvoiceFailed(event, env) {
  const invoice = event.data.object;
  if (!invoice.subscription) return;
  const found = await findSignupBySubscription(env, invoice.subscription);
  if (!found) return;
  const updates = {
    payment_status: "PAYMENT FAILED - action needed",
    payment_failed_at: (/* @__PURE__ */ new Date()).toISOString()
  };
  await rtdbUpdate(env, `${COHORT_SIGNUPS_PATH}/${found.id}`, updates);
  await pushCohortFeedEvent(env, {
    kind: "payment_failed",
    title: `PAYMENT FAILED: ${found.record.name || found.record.email}`,
    cohort: found.record.cohort,
    email: found.record.email,
    name: found.record.name
  });
}
__name(handleInvoiceFailed, "handleInvoiceFailed");
async function handleSubscriptionDeleted(event, env) {
  const sub = event.data.object;
  const found = await findSignupBySubscription(env, sub.id);
  if (!found) return;
  await rtdbUpdate(env, `${COHORT_SIGNUPS_PATH}/${found.id}`, {
    payment_status: "All payments complete",
    subscription_ended_at: (/* @__PURE__ */ new Date()).toISOString(),
    next_payment_date: null,
    next_payment_amount: 0
  });
}
__name(handleSubscriptionDeleted, "handleSubscriptionDeleted");
async function pushCohortFeedEvent(env, e) {
  if (!env.SCALO_STATS) return;
  const KEY = "feed:events";
  const events = await env.SCALO_STATS.get(KEY, { type: "json" }) || [];
  const entry = {
    ...e,
    source: "stripe",
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
    ts: Date.now()
  };
  events.unshift(entry);
  if (events.length > 500) events.length = 500;
  await env.SCALO_STATS.put(KEY, JSON.stringify(events));
}
__name(pushCohortFeedEvent, "pushCohortFeedEvent");
async function pushWaitlistFeedEvent(env, record) {
  if (!env.SCALO_STATS) return;
  const KEY = "feed:events";
  const events = await env.SCALO_STATS.get(KEY, { type: "json" }) || [];
  const entry = {
    type: "waitlist",
    author: record.name || record.email || "Waitlist signup",
    email: record.email,
    leadSource: record.source,
    cohort: record.cohort,
    instagram: record.instagram || "",
    phone: record.phone || "",
    source: "waitlist",
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
    ts: Date.now()
  };
  events.unshift(entry);
  if (events.length > 500) events.length = 500;
  await env.SCALO_STATS.put(KEY, JSON.stringify(events));
}
__name(pushWaitlistFeedEvent, "pushWaitlistFeedEvent");
var worker_default = {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(Promise.all([
      runDailyScrape(env),
      pingSupabase(env)
    ]));
  },
  async fetch(request, env) {
    const corsHeaders = buildCorsHeaders(request);
    const url = new URL(request.url);
    if (request.method === "OPTIONS") {
      if (url.pathname === "/waitlist-signup" || url.pathname === "/kit-webhook" || url.pathname === "/founding-count") {
        return new Response(null, {
          status: 204,
          headers: {
            ...corsHeaders,
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
            "Vary": "Origin"
          }
        });
      }
      return new Response(null, { headers: corsHeaders });
    }
    if (url.pathname === "/supabase-session") {
      if (request.method !== "POST") {
        return new Response("Method not allowed", { status: 405, headers: corsHeaders });
      }
      if (!env.SUPABASE_JWT_SECRET) {
        return new Response(JSON.stringify({ error: "SUPABASE_JWT_SECRET not configured" }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      const authHeader = request.headers.get("Authorization") || "";
      const idToken = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
      if (!idToken) {
        return new Response(JSON.stringify({ error: "Missing Authorization: Bearer <firebase_id_token>" }), {
          status: 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      try {
        const fb = await verifyFirebaseIdToken(idToken);
        const now = Math.floor(Date.now() / 1e3);
        const expiresIn = 3600;
        const claims = {
          iss: "scalo-worker",
          sub: fb.sub,
          email: fb.email || null,
          role: "authenticated",
          aud: "authenticated",
          iat: now,
          exp: now + expiresIn
        };
        const token = await signSupabaseJwt(claims, env.SUPABASE_JWT_SECRET);
        return new Response(JSON.stringify({
          access_token: token,
          token_type: "bearer",
          expires_in: expiresIn,
          user: { id: fb.sub, email: fb.email || null }
        }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: "Invalid Firebase token: " + e.message }), {
          status: 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }
    if (url.pathname === "/stripe-webhook") {
      return handleStripeWebhook(request, env, corsHeaders);
    }
    if (url.pathname === "/waitlist-signup") {
      return handleWaitlistSignup(request, env, corsHeaders);
    }
    if (url.pathname === "/kit-webhook") {
      return handleKitWebhook(request, env, corsHeaders);
    }
    if (url.pathname === "/founding-count") {
      return handleFoundingCount(request, env, corsHeaders);
    }
    const TEAM_PATHS = /* @__PURE__ */ new Set(["/feed"]);
    if (TEAM_PATHS.has(url.pathname)) {
      try {
        await requireSignedIn(request);
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), {
          status: e.status || 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }
    const isGcalPath = url.pathname.startsWith("/gcal/");
    if (!PUBLIC_PATHS.has(url.pathname) && !TEAM_PATHS.has(url.pathname) && !isGcalPath) {
      try {
        await requireAdmin(request);
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), {
          status: e.status || 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }
    if (url.pathname === "/scrape-ig" || url.pathname === "/scrape-yt") {
      if (!env.APIFY_TOKEN) {
        return new Response(JSON.stringify({ error: "APIFY_TOKEN not configured" }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      const handle = url.searchParams.get("handle") || url.searchParams.get("profile") || url.searchParams.get("channel");
      const days = parseInt(url.searchParams.get("days") || "90", 10);
      try {
        const items = url.pathname === "/scrape-ig" ? await scrapeIgTopReels(handle, env.APIFY_TOKEN, days) : await scrapeYtTopVideos(handle, env.APIFY_TOKEN, days);
        return new Response(JSON.stringify({ items }), {
          headers: { ...corsHeaders, "Content-Type": "application/json", "Cache-Control": "max-age=300" }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }
    if (url.pathname === "/profile-ig" || url.pathname === "/profile-yt") {
      if (!env.APIFY_TOKEN) {
        return new Response(JSON.stringify({ error: "APIFY_TOKEN not configured" }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      const handle = url.searchParams.get("handle") || url.searchParams.get("channel") || url.searchParams.get("profile");
      try {
        const data = url.pathname === "/profile-ig" ? await scrapeIgProfile(handle, env.APIFY_TOKEN) : await scrapeYtChannel(handle, env.APIFY_TOKEN);
        return new Response(JSON.stringify(data), {
          headers: { ...corsHeaders, "Content-Type": "application/json", "Cache-Control": "max-age=300" }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }
    if (url.pathname === "/stats-history") {
      if (!env.SCALO_STATS) {
        return new Response(JSON.stringify({ error: "KV not configured" }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      const [scalo, tbh] = await Promise.all([
        env.SCALO_STATS.get("history:scalo_with_tim", { type: "json" }),
        env.SCALO_STATS.get("history:tim_brace_hair", { type: "json" })
      ]);
      return new Response(JSON.stringify({
        scalo_with_tim: scalo || [],
        tim_brace_hair: tbh || []
      }), {
        headers: { ...corsHeaders, "Content-Type": "application/json", "Cache-Control": "max-age=300" }
      });
    }
    if (url.pathname === "/revenue-series") {
      if (!env.STRIPE_KEY) {
        return new Response(JSON.stringify({ error: "STRIPE_KEY not configured" }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      try {
        const days = url.searchParams.get("days") || "30";
        const data = await getRevenueSeries(env.STRIPE_KEY, days);
        return new Response(JSON.stringify(data), {
          headers: { ...corsHeaders, "Content-Type": "application/json", "Cache-Control": "max-age=60" }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }
    if (url.pathname === "/library") {
      if (!env.SCALO_STATS) {
        return new Response(JSON.stringify({ error: "KV not configured" }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      const rawType = url.searchParams.get("type");
      const typeMap = { sop: "sop", sops: "sop", leadmag: "leadmag", leadmags: "leadmag", toolkit: "toolkit" };
      const type = typeMap[rawType];
      if (!type) {
        return new Response(JSON.stringify({ error: "invalid type" }), {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      const KEY = "library:" + type;
      if (request.method === "GET") {
        const items = await env.SCALO_STATS.get(KEY, { type: "json" }) || null;
        return new Response(JSON.stringify({ items }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      if (request.method === "PUT" || request.method === "POST") {
        try {
          const body = await request.json();
          if (!Array.isArray(body.items)) throw new Error("items must be array");
          await env.SCALO_STATS.put(KEY, JSON.stringify(body.items));
          return new Response(JSON.stringify({ ok: true, count: body.items.length }), {
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        } catch (err) {
          return new Response(JSON.stringify({ error: err.message }), {
            status: 500,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
      }
      return new Response("Method not allowed", { status: 405, headers: corsHeaders });
    }
    if (url.pathname === "/close-auth" || url.pathname === "/close-log") {
      if (!env.SCALO_STATS) {
        return new Response(JSON.stringify({ error: "KV not configured" }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      const KEY = url.pathname === "/close-auth" ? "close_auth_users" : "close_log_entries";
      if (request.method === "GET") {
        const data = await env.SCALO_STATS.get(KEY, { type: "json" }) || [];
        return new Response(JSON.stringify({ items: data }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      if (request.method === "POST") {
        try {
          const body = await request.json();
          if (body.action === "replace") {
            await env.SCALO_STATS.put(KEY, JSON.stringify(body.items || []));
            return new Response(JSON.stringify({ ok: true }), {
              headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
          }
          const existing = await env.SCALO_STATS.get(KEY, { type: "json" }) || [];
          existing.push(body.item);
          await env.SCALO_STATS.put(KEY, JSON.stringify(existing));
          return new Response(JSON.stringify({ ok: true, count: existing.length }), {
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        } catch (err) {
          return new Response(JSON.stringify({ error: err.message }), {
            status: 500,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
      }
      return new Response("Method not allowed", { status: 405, headers: corsHeaders });
    }
    if (url.pathname === "/feed") {
      if (!env.SCALO_STATS) {
        return new Response(JSON.stringify({ error: "KV not configured" }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      const KEY = "feed:events";
      if (request.method === "GET") {
        const events = await env.SCALO_STATS.get(KEY, { type: "json" }) || [];
        return new Response(JSON.stringify({ events }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      if (request.method === "POST") {
        try {
          const entry = await request.json();
          const events = await env.SCALO_STATS.get(KEY, { type: "json" }) || [];
          const event = {
            ...entry,
            id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
            ts: Date.now()
          };
          events.unshift(event);
          if (events.length > 500) events.length = 500;
          await env.SCALO_STATS.put(KEY, JSON.stringify(events));
          return new Response(JSON.stringify({ ok: true, event }), {
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        } catch (err) {
          return new Response(JSON.stringify({ error: err.message }), {
            status: 500,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
      }
      if (request.method === "DELETE") {
        const id = url.searchParams.get("id");
        if (!id) return new Response(JSON.stringify({ error: "missing id" }), {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
        const events = await env.SCALO_STATS.get(KEY, { type: "json" }) || [];
        const filtered = events.filter((e) => e.id !== id);
        await env.SCALO_STATS.put(KEY, JSON.stringify(filtered));
        return new Response(JSON.stringify({ ok: true }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      return new Response("Method not allowed", { status: 405, headers: corsHeaders });
    }
    const GCAL_REDIRECT = url.origin + "/gcal/callback";
    const GCAL_SCOPE = "https://www.googleapis.com/auth/calendar.readonly";
    if (url.pathname === "/gcal/auth") {
      if (!env.GOOGLE_CLIENT_ID) {
        return new Response(JSON.stringify({ error: "GOOGLE_CLIENT_ID not configured" }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      const token = url.searchParams.get("token") || "";
      if (!token) {
        return new Response(JSON.stringify({ error: "Missing ?token= (Firebase ID token)" }), {
          status: 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      let userId;
      try {
        const payload = await verifyFirebaseIdToken(token);
        userId = payload.sub;
      } catch (e) {
        return new Response(JSON.stringify({ error: "Invalid auth token: " + e.message }), {
          status: 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      const params = new URLSearchParams({
        client_id: env.GOOGLE_CLIENT_ID,
        redirect_uri: GCAL_REDIRECT,
        response_type: "code",
        scope: GCAL_SCOPE,
        access_type: "offline",
        prompt: "consent",
        include_granted_scopes: "true",
        state: userId
      });
      return Response.redirect("https://accounts.google.com/o/oauth2/v2/auth?" + params.toString(), 302);
    }
    if (url.pathname === "/gcal/callback") {
      const code = url.searchParams.get("code");
      const userId = url.searchParams.get("state") || "default";
      if (!code) return new Response("Missing code", { status: 400, headers: corsHeaders });
      try {
        const body = new URLSearchParams({
          code,
          client_id: env.GOOGLE_CLIENT_ID,
          client_secret: env.GOOGLE_CLIENT_SECRET,
          redirect_uri: GCAL_REDIRECT,
          grant_type: "authorization_code"
        });
        const tokRes = await fetch("https://oauth2.googleapis.com/token", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body
        });
        const tok = await tokRes.json();
        if (!tokRes.ok || !tok.refresh_token) {
          return new Response("Token exchange failed: " + JSON.stringify(tok), { status: 500, headers: corsHeaders });
        }
        await env.SCALO_STATS.put("gcal:refresh_token:" + userId, tok.refresh_token);
        return new Response(`<html><body style="font-family:system-ui;text-align:center;padding:80px;"><h2>Google Calendar connected ✓</h2><p>You can close this window and return to SCALO OS.</p><script>setTimeout(()=>window.close(),1500);<\/script></body></html>`, {
          headers: { ...corsHeaders, "Content-Type": "text/html" }
        });
      } catch (e) {
        return new Response("OAuth error: " + e.message, { status: 500, headers: corsHeaders });
      }
    }
    if (url.pathname === "/gcal/status") {
      let userId;
      try {
        userId = (await requireSignedIn(request)).sub;
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), {
          status: e.status || 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      const has = !!(env.SCALO_STATS && await env.SCALO_STATS.get("gcal:refresh_token:" + userId));
      return new Response(JSON.stringify({ connected: has }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }
    if (url.pathname === "/gcal/disconnect") {
      let userId;
      try {
        userId = (await requireSignedIn(request)).sub;
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), {
          status: e.status || 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      if (env.SCALO_STATS) await env.SCALO_STATS.delete("gcal:refresh_token:" + userId);
      return new Response(JSON.stringify({ ok: true }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }
    if (url.pathname === "/gcal/events") {
      let userId;
      try {
        userId = (await requireSignedIn(request)).sub;
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), {
          status: e.status || 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      try {
        const refresh = await env.SCALO_STATS.get("gcal:refresh_token:" + userId);
        if (!refresh) {
          return new Response(JSON.stringify({ error: "not_connected" }), {
            status: 401,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        const tokRes = await fetch("https://oauth2.googleapis.com/token", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            client_id: env.GOOGLE_CLIENT_ID,
            client_secret: env.GOOGLE_CLIENT_SECRET,
            refresh_token: refresh,
            grant_type: "refresh_token"
          })
        });
        const tok = await tokRes.json();
        if (!tok.access_token) throw new Error("Refresh failed: " + JSON.stringify(tok));
        const timeMin = (/* @__PURE__ */ new Date()).toISOString();
        const timeMax = new Date(Date.now() + 14 * 864e5).toISOString();
        const evRes = await fetch("https://www.googleapis.com/calendar/v3/calendars/primary/events?" + new URLSearchParams({
          timeMin,
          timeMax,
          singleEvents: "true",
          orderBy: "startTime",
          maxResults: "25"
        }), { headers: { Authorization: "Bearer " + tok.access_token } });
        const ev = await evRes.json();
        const items = (ev.items || []).map((e) => ({
          id: e.id,
          title: e.summary || "(no title)",
          start: e.start?.dateTime || e.start?.date,
          end: e.end?.dateTime || e.end?.date,
          allDay: !e.start?.dateTime,
          location: e.location || "",
          link: e.htmlLink || "",
          attendees: (e.attendees || []).length
        }));
        return new Response(JSON.stringify({ items }), {
          headers: { ...corsHeaders, "Content-Type": "application/json", "Cache-Control": "max-age=120" }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }
    if (url.pathname === "/analyze" && request.method === "POST") {
      if (!env.ANTHROPIC_KEY) {
        return new Response(JSON.stringify({ error: "ANTHROPIC_KEY not configured" }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      try {
        const body = await request.json();
        const { url: sourceUrl, account, accountLabel, accountContext, sop, goal, platform, tone } = body;
        if (!sourceUrl) throw new Error("Missing URL");
        const detectedPlatform = detectPlatform(sourceUrl);
        if (!detectedPlatform) throw new Error("URL not recognised — paste an Instagram Reel or YouTube link");
        let source;
        if (detectedPlatform === "youtube") {
          const videoId = extractYtVideoId(sourceUrl);
          if (!videoId) throw new Error("Could not extract YouTube video ID");
          const yt = await fetchYouTubeTranscript(videoId, env.APIFY_TOKEN);
          source = {
            platform: "youtube",
            url: sourceUrl,
            title: yt.title,
            caption: yt.description || "",
            transcript: yt.transcript || "",
            views: yt.views || 0,
            likes: 0,
            thumbnail: `https://img.youtube.com/vi/${videoId}/hqdefault.jpg`
          };
        } else {
          if (!env.APIFY_TOKEN) throw new Error("APIFY_TOKEN not configured — needed for Instagram");
          const ig = await fetchInstagramPost(sourceUrl, env.APIFY_TOKEN);
          let igTranscript = "";
          if (ig.videoUrl) {
            igTranscript = await transcribeVideoAudio(env, ig.videoUrl) || "";
          }
          source = {
            platform: "instagram",
            url: sourceUrl,
            title: ig.title,
            caption: ig.caption,
            transcript: igTranscript,
            views: ig.views,
            likes: ig.likes,
            thumbnail: ig.thumbnail
          };
        }
        const contentText = source.transcript || source.caption || source.title;
        if (!contentText || contentText.length < 10) throw new Error("Not enough content found to analyze — the video may have no captions or transcript");
        const systemPrompt = `You are a senior content strategist and scriptwriter for "${accountLabel || "the brand"}".
Brand context: ${accountContext || "Content creator brand"}

${sop ? "Brand SOP & Voice Guidelines:\n" + sop + "\n" : ""}
TASK:
You are given a reference piece of content from ${detectedPlatform}. Your job:
1. ANALYZE it: score 1-5 on how well it fits this brand/niche
2. GENERATE a full adapted script that sounds like this brand's voice — inspired by the reference but NOT copying it

SCORING CRITERIA (each 1-5):
- hookStrength: How strong is the opening hook? Would it stop a scroll?
- brandFit: How well does this content style/topic match the brand voice?
- icpRelevance: How relevant is this to the ideal client/audience?
- monetisability: Can this be adapted to drive business results (leads, sales, authority)?
- adaptability: How easily can this concept be rewritten for our brand?

Overall score = average of the 5 criteria, rounded to nearest integer.

SCRIPT GENERATION:
Using the reference as INSPIRATION, generate a FULL word-for-word script (45-60 seconds spoken aloud). This must be ready to film with minimal tweaks.

VOICE & STYLE RULES:
1. ADAPT TO THE CONTENT. Match the script style to what the reference video is about. A math/numbers video should use math breakdowns. A story video should use storytelling. A mindset video should hit emotional beats. Don't force one style on every topic.
2. ALWAYS USE "YOU" LANGUAGE. Speak directly to the viewer. "You need…" "Your business…" "Here's what you're missing…" Make it feel like a 1-on-1 conversation, not a broadcast.
3. SHORT PUNCHY LINES. Each line is its own beat. One thought per line. Written like someone TALKING on camera, not writing. Fragments are good. "Wrong." "Now watch this…" "That's the difference."
4. NO GENERIC FLUFF. Never write "In today's competitive landscape" or "Let me share something with you." Be direct, blunt, real. Slightly sweary when it hits harder.
5. WEAVE IN PROOF NATURALLY. If the SOP contains student results, case studies, or specific numbers — use the ones that FIT this specific video topic. Don't shoehorn proof that doesn't match. If no specific proof fits, use a credible but general reference ("I've seen this with my students time and time again").
6. ALWAYS CONNECT TO THE PRODUCT/SYSTEM. Every script should naturally build awareness of SCALO (or the relevant product). Not a hard sell — weave it in as the solution. "That's exactly what SCALO is built for." "This is the system behind it." Make the viewer curious about the product without it feeling forced.
7. END WITH A SYSTEM-BACKED CTA. Give viewers a specific action — comment a keyword, watch a linked video, check bio. Connect it to SCALO or a specific resource. Not just "follow for more."

The script should feel like Tim talking to camera — direct, personal ("you"), backed by real proof where it fits, and always building towards SCALO as the system that makes it all work.

Return these fields:
- hook: The opening 1-2 sentences (scroll-stopper that makes "you" the subject)
- goal: One sentence on what this piece achieves for the brand
- body: Array of 15-25 short lines that form the FULL spoken script (each line is 1-2 sentences MAX, written exactly as spoken on camera — short, punchy, conversational, adapted to the topic)
- cta: The closing call-to-action (2-3 sentences, includes a comment keyword and ties to SCALO or a specific resource)
- captionDraft: A full social media caption with hashtags
- estimatedDuration: Target "45-60s"
- funnelStage: "TOF" (awareness), "MOF" (consideration), or "BOF" (conversion)

Goal direction: ${goal || "Conversion"}
Target platform: ${platform || "Instagram"}
Tone: ${tone || "Direct"}

Return ONLY valid JSON matching this exact structure (no markdown, no explanation):
{
  "analysis": {
    "score": 4,
    "scoreBreakdown": { "hookStrength": 5, "brandFit": 3, "icpRelevance": 4, "monetisability": 4, "adaptability": 4 },
    "reasoning": "One paragraph explaining the score and why this reference works or doesn't for the brand."
  },
  "script": {
    "hook": "opening line",
    "goal": "what this achieves",
    "body": ["Beat 1", "Beat 2", "Beat 3", "Beat 4"],
    "cta": "call to action",
    "captionDraft": "full caption with hashtags",
    "estimatedDuration": "60s",
    "funnelStage": "TOF"
  }
}`;
        const userMessage = `Reference content from ${detectedPlatform}:
Title: ${source.title || "(no title)"}
${source.transcript ? "Transcript:\n" + source.transcript.slice(0, 6e3) : ""}
${source.caption ? "Caption:\n" + source.caption.slice(0, 2e3) : ""}
Views: ${source.views.toLocaleString()}${source.likes ? ", Likes: " + source.likes.toLocaleString() : ""}

Analyze this reference and generate an adapted script for ${accountLabel || "the brand"}.`;
        const parsed = await callClaude(env, systemPrompt, userMessage);
        return new Response(JSON.stringify({
          source,
          analysis: parsed.analysis || { score: 0, scoreBreakdown: {}, reasoning: "" },
          script: parsed.script || {}
        }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }
    if (url.pathname === "/generate" && request.method === "POST") {
      if (!env.ANTHROPIC_KEY) {
        return new Response(JSON.stringify({ error: "ANTHROPIC_KEY not configured" }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      try {
        const body = await request.json();
        const { account, accountLabel, accountContext, format, stage, volume, sop, mode } = body;
        if (!account || !accountLabel) throw new Error("Missing account info");
        const isConceptingLab = mode === "concepting_lab";
        const count = Math.min(volume || 3, 10);
        let systemPrompt;
        if (isConceptingLab) {
          systemPrompt = `You are a senior content strategist for the brand "${accountLabel}".
Brand context: ${accountContext || "Content creator brand"}

The user will provide a brief with Goal, Platform, Tone, and optionally a Trend reference.
Generate exactly ${count} original short-form content concepts.

For each concept, return a JSON object with these exact fields:
- "hook": A punchy opening line / hook (the scroll-stopper)
- "title": A working title for the piece
- "format": The content format (e.g. "Reel", "TikTok", "YouTube Short")
- "script_outline": An array of 4-6 script beats (strings) that outline the video flow
- "caption_angle": A one-sentence caption direction / CTA approach

Return ONLY a JSON object: { "ideas": [ ... ] }
No markdown, no explanation, just valid JSON.`;
        } else {
          const isLong = format === "long";
          systemPrompt = `You are a senior content strategist for the brand "${accountLabel}".
Brand context: ${accountContext || "Content creator brand"}

${sop ? "Brand SOP / Guidelines:\n" + sop + "\n" : ""}
Generate exactly ${count} ${isLong ? "long-form video" : "short-form content"} ideas at the "${stage || "idea"}" stage.

For each idea, return a JSON object with these exact fields:
- "title": A compelling working title
- "format": ${isLong ? 'The video type (e.g. "Tutorial", "Vlog", "Case Study", "Interview")' : 'The content format (e.g. "Reel", "Carousel", "Story Sequence")'}
- "funnelStage": "${stage || "idea"}"
- "goal": A one-sentence goal / key message
- "scriptOutline": { "hook": "opening line", "body": ["beat 1", "beat 2", "beat 3"], "cta": "closing CTA" }
${isLong ? '- "targetLength": Suggested duration (e.g. "12–15 min")\n- "thumbnailConcept": A one-line thumbnail idea' : '- "duration": Suggested duration (e.g. "60s", "30s")\n- "inspirationSource": A brief note on the creative angle'}

Return ONLY a JSON object: { "ideas": [ ... ] }
No markdown, no explanation, just valid JSON.`;
        }
        const userMessage = isConceptingLab ? `Brief: ${sop || "Generate content concepts for this brand."}` : `Generate ${count} ${format === "long" ? "long-form" : "short-form"} content ideas for the "${stage}" stage.${sop ? "\n\nSOP context: " + sop : ""}`;
        const parsed = await callClaude(env, systemPrompt, userMessage);
        const ideas = Array.isArray(parsed.ideas) ? parsed.ideas : Array.isArray(parsed) ? parsed : [];
        return new Response(JSON.stringify({ ideas }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }
    if (url.pathname !== "/stats") {
      return new Response("SCALO OS Stripe Worker — /stats endpoint only", {
        status: 404,
        headers: corsHeaders
      });
    }
    if (!env.STRIPE_KEY) {
      return new Response(JSON.stringify({ error: "STRIPE_KEY not configured" }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }
    try {
      const data = await getStats(env.STRIPE_KEY);
      return new Response(JSON.stringify(data), {
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json",
          "Cache-Control": "max-age=60"
        }
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }
  }
};
export {
  worker_default as default
};

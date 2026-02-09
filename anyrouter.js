/**
 * AnyRouter 签到脚本（支持 Cloudflare Worker + Node.js 双环境）
 *
 * 运行环境：
 * - Node.js 18+
 * - Cloudflare Worker（Scheduled Trigger + HTTP 反代）
 *
 * 环境变量：
 * - COOKIES（必填，签到用）：多账号 session 值，支持「换行分隔 / 逗号分隔 / JSON数组」
 * - UPSTREAM（可选）：默认 https://anyrouter.top
 * - TG_BOT_TOKEN（可选）
 * - TG_CHAT_ID（可选）
 *
 * CF Worker 功能：
 * - GET / : 健康检查
 * - 其他路径 : 反代到 UPSTREAM，自动注入 acw_sc__v2
 * - Cron Trigger : 自动签到
 */

const DEFAULT_UPSTREAM = "https://anyrouter.top";

const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
  "AppleWebKit/537.36 (KHTML, like Gecko) " +
  "Chrome/131.0.0.0 Safari/537.36";

/** ======== 运行时检测 ======== */

const IS_NODE =
  typeof process !== "undefined" &&
  !!(process.versions && process.versions.node);

function isNodeDirectRun() {
  if (!IS_NODE) return false;
  try {
    const entry = String(process.argv[1] || "").replace(/\\/g, "/").toLowerCase();
    if (!entry) return false;
    let selfPath = decodeURIComponent(new URL(import.meta.url).pathname);
    if (/^\/[A-Za-z]:\//.test(selfPath)) selfPath = selfPath.slice(1);
    const self = selfPath.replace(/\\/g, "/").toLowerCase();
    const entryIsAbs = /^(?:[A-Za-z]:\/|\/)/.test(entry);
    return entryIsAbs ? self === entry : self.split("/").pop() === entry.split("/").pop();
  } catch {
    return false;
  }
}

function normalizeBaseUrl(raw, fallback) {
  const base = (raw || fallback || "").trim();
  return base.replace(/\/+$/, "");
}

function parseCookies(raw) {
  if (!raw) return [];
  const trimmed = String(raw).trim();
  if (!trimmed) return [];

  // JSON 数组：["session1","session2"]
  if (trimmed.startsWith("[")) {
    try {
      const arr = JSON.parse(trimmed);
      if (Array.isArray(arr)) {
        return arr.map((c) => String(c).trim()).filter(Boolean);
      }
    } catch {}
  }

  // 换行/逗号分隔
  return trimmed
    .split(/[\n,]+/g)
    .map((c) => c.trim())
    .filter(Boolean);
}

/** ======== 动态 Cookie：acw_sc__v2（unsbox + XOR） ======== */

const XOR_KEY = "3000176000856006061501533003690027800375";
const UNSBOX_TABLE = [
  0xf, 0x23, 0x1d, 0x18, 0x21, 0x10, 0x1, 0x26, 0xa, 0x9, 0x13, 0x1f, 0x28,
  0x1b, 0x16, 0x17, 0x19, 0xd, 0x6, 0xb, 0x27, 0x12, 0x14, 0x8, 0xe, 0x15,
  0x20, 0x1a, 0x2, 0x1e, 0x7, 0x4, 0x11, 0x5, 0x3, 0x1c, 0x22, 0x25,
  0xc, 0x24,
];

function computeAcwCookie(arg1) {
  // unsbox：根据置换表重排（表内值从 1 开始）
  const unsboxed = UNSBOX_TABLE.map((i) => arg1[i - 1]).join("");

  // hexXor：与 key 异或（两位 hex 一组）
  let out = "";
  for (let i = 0; i < 40; i += 2) {
    const a = parseInt(unsboxed.slice(i, i + 2), 16);
    const b = parseInt(XOR_KEY.slice(i, i + 2), 16);
    out += ((a ^ b).toString(16)).padStart(2, "0");
  }
  return `acw_sc__v2=${out}`;
}

async function getAcwCookie(targetUrl) {
  try {
    const resp = await fetch(targetUrl.toString(), {
      method: "GET",
      headers: { "User-Agent": UA },
      redirect: "manual",
    });
    const html = await resp.text();
    const m = html.match(/var\s+arg1\s*=\s*'([0-9a-fA-F]{40})'/);
    if (!m) return null;
    return computeAcwCookie(m[1]);
  } catch {
    return null;
  }
}

/** ======== 业务：签到 ======== */

async function signInWithDynamicCookie(upstream, session) {
  const signUrl = new URL("/api/user/sign_in", upstream);

  // 1) 获取 acw_sc__v2（优先 sign_in，失败降级 self）
  const candidates = [signUrl, new URL("/api/user/self", upstream)];

  let acwCookie = null;
  for (const apiUrl of candidates) {
    const targetUrl = new URL(apiUrl.pathname + apiUrl.search, upstream);
    acwCookie = await getAcwCookie(targetUrl);
    if (acwCookie) break;
  }

  if (!acwCookie) {
    return { ok: false, msg: "❌ 获取动态 Cookie 失败: arg1 not found / request failed" };
  }

  // 2) 带动态 cookie + session 发起签到
  let resp;
  try {
    resp = await fetch(signUrl.toString(), {
      method: "POST",
      headers: {
        "User-Agent": UA,
        Cookie: `${acwCookie}; session=${session}`,
        "Content-Type": "application/json",
        Accept: "application/json, text/plain, */*",
        Origin: upstream,
        Referer: `${upstream}/`,
      },
      body: "",
    });
  } catch (err) {
    return { ok: false, msg: `❌ 请求异常: ${String(err)}` };
  }

  if (resp.status === 401) return { ok: false, msg: "❌ session 无效(401)" };

  const bodyText = await resp.text().catch(() => "");
  if (!resp.ok) return { ok: false, msg: `❌ HTTP ${resp.status}: ${bodyText}` };

  let data;
  try {
    data = JSON.parse(bodyText);
  } catch {
    return { ok: false, msg: `❌ 响应非JSON: ${bodyText}` };
  }

  const success = data?.success;
  const message = String(data?.message || "").trim();

  if (success === true) return { ok: true, msg: message ? `✅ ${message}` : "✅ 今日已签到" };
  if (success === false) {
    return {
      ok: false,
      msg: message ? `❌ ${message}` : `❌ 签到失败: ${JSON.stringify(data)}`,
    };
  }

  return { ok: true, msg: `✅ 返回: ${JSON.stringify(data)}` };
}

/** ======== Telegram（可选） ======== */

async function sendTelegram(env, messageHtml) {
  const token = (env.TG_BOT_TOKEN || "").trim();
  const chatId = (env.TG_CHAT_ID || "").trim();
  if (!token || !chatId) return { sent: false, reason: "not_configured" };

  const url = `https://api.telegram.org/bot${token}/sendMessage`;
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: chatId, text: messageHtml, parse_mode: "HTML" }),
  });

  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    return { sent: false, reason: `http_${resp.status}`, detail: text };
  }
  return { sent: true };
}

/** ======== main ======== */

async function main(envArg) {
  const env = envArg || (IS_NODE ? process.env : {});
  const upstream = normalizeBaseUrl(env.UPSTREAM, DEFAULT_UPSTREAM);
  const sessions = parseCookies(env.COOKIES);

  if (sessions.length === 0) {
    console.error("❌ 未配置 COOKIES（请设置环境变量 COOKIES，内容为 session 值）");
    return { ok: false, exitCode: 1, message: "COOKIES is empty" };
  }

  const results = ["🔔 <b>AnyRouter 签到结果</b>\n"];
  let successCount = 0;
  let failCount = 0;

  for (let i = 0; i < sessions.length; i += 1) {
    const { ok, msg } = await signInWithDynamicCookie(upstream, sessions[i]);
    results.push(`账号 #${i + 1}: ${msg}`);
    if (ok) successCount += 1;
    else failCount += 1;
  }

  const summary = `\n📊 <b>汇总</b>: 成功 ${successCount} / 失败 ${failCount} / 共 ${sessions.length}`;
  results.push(summary);

  const fullMessage = results.join("\n");

  // 控制台输出（不打印 session）
  const startedAt = new Date().toISOString();
  console.log(
    `[anyrouter] startedAt=${startedAt} upstream=${upstream} 成功=${successCount} 失败=${failCount} 总数=${sessions.length}`,
  );
  for (const line of results) console.log(line);

  // Telegram（可选）
  const telegram = await sendTelegram(env, fullMessage);
  if (!telegram.sent) {
    console.log(`[anyrouter] telegram_not_sent reason=${telegram.reason || "unknown"}`);
  }

  const exitCode = failCount === 0 ? 0 : 1;
  return { ok: exitCode === 0, exitCode, message: fullMessage };
}

/** ======== CF Worker Handlers ======== */

async function fetchHandler(request, env, ctx) {
  const url = new URL(request.url);
  const upstream = normalizeBaseUrl(env.UPSTREAM, DEFAULT_UPSTREAM);

  // 根路径返回状态
  if (url.pathname === "/") {
    return new Response("AnyRouter Proxy OK", { status: 200 });
  }

  // 反代：自动注入 acw_sc__v2
  const targetUrl = new URL(url.pathname + url.search, upstream);
  const acwCookie = await getAcwCookie(targetUrl);
  if (!acwCookie) {
    return new Response("Failed to obtain acw_sc__v2 cookie", { status: 502 });
  }

  const headers = new Headers(request.headers);
  const originalCookie = request.headers.get("cookie");
  headers.set("cookie", [acwCookie, originalCookie].filter(Boolean).join("; "));
  headers.set("origin", upstream);
  headers.set("referer", `${upstream}/`);
  headers.set("host", new URL(upstream).host);
  headers.delete("content-length");

  const init = { method: request.method, headers, redirect: "manual" };
  if (!["GET", "HEAD"].includes(request.method)) {
    init.body = await request.arrayBuffer();
  }

  const resp = await fetch(targetUrl.toString(), init);
  return new Response(resp.body, { status: resp.status, headers: resp.headers });
}

async function scheduledHandler(event, env, ctx) {
  const promise = main(env);
  if (ctx?.waitUntil) ctx.waitUntil(promise);
  else await promise;
}

export default {
  fetch: fetchHandler,
  scheduled: scheduledHandler,
};

/** ======== Node.js 入口 ======== */

if (IS_NODE && isNodeDirectRun()) {
  main()
    .then((result) => {
      process.exitCode = result.exitCode;
    })
    .catch((e) => {
      console.error(`[anyrouter] fatal: ${String(e)}`);
      process.exitCode = 1;
    });
}

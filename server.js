import httpProxy from "http-proxy";
import https from "https";
import crypto from "crypto";
import assert from "assert";
import zlib from "zlib";
import { URL } from "url";

export const config = {
  api: {
    bodyParser: false, // REQUIRED for proxying
    externalResolver: true
  }
};

// -------------------- CONSTANTS --------------------

const ALLOWED_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
const ALLOWED_PROTOS = ["http", "https"];
const ALLOWED_GZIP_METHODS = ["transform", "decode", "append"];

const DEFAULT_PROTO = "https";
const DEFAULT_USERAGENT = "Mozilla";

// -------------------- ENV --------------------

const ACCESS_KEY = process.env.ACCESS_KEY && Buffer.from(process.env.ACCESS_KEY);
const USE_WHITELIST = process.env.USE_WHITELIST === "true";
const USE_OVERRIDE_STATUS = process.env.USE_OVERRIDE_STATUS === "true";
const REWRITE_ACCEPT_ENCODING = process.env.REWRITE_ACCEPT_ENCODING === "true";
const APPEND_HEAD = process.env.APPEND_HEAD === "true";
const GZIP_METHOD = process.env.GZIP_METHOD;

assert.ok(ACCESS_KEY, "Missing ACCESS_KEY");
assert.ok(ALLOWED_GZIP_METHODS.includes(GZIP_METHOD), "Invalid GZIP_METHOD");

// -------------------- HOSTS --------------------

const getHosts = (hosts) => {
  if (!hosts) return [];
  return hosts.split(",").map((host) => {
    new URL(`${DEFAULT_PROTO}://${host}`);
    return { host };
  });
};

const ALLOWED_HOSTS = getHosts(process.env.ALLOWED_HOSTS);

// -------------------- PROXIES --------------------

const httpsProxy = httpProxy.createProxyServer({
  agent: new https.Agent({ rejectUnauthorized: false }),
  changeOrigin: true,
  selfHandleResponse: true
});

const httpProxyServer = httpProxy.createProxyServer({
  changeOrigin: true,
  selfHandleResponse: true
});

// -------------------- HELPERS --------------------

const writeErr = (res, status, message) => {
  res.statusCode = status;
  res.end(message);
};

const onProxyReq = (proxyReq) => {
  proxyReq.setHeader(
    "User-Agent",
    proxyReq.getHeader("proxy-override-user-agent") || DEFAULT_USERAGENT
  );

  if (REWRITE_ACCEPT_ENCODING) {
    proxyReq.setHeader("Accept-Encoding", "gzip");
  }

  proxyReq.removeHeader("roblox-id");
  proxyReq.removeHeader("proxy-access-key");
  proxyReq.removeHeader("proxy-target");
};

const onProxyRes = (proxyRes, req, res) => {
  if (USE_OVERRIDE_STATUS) proxyRes.statusCode = 200;

  Object.entries(proxyRes.headers).forEach(([k, v]) => {
    res.setHeader(k, v);
  });

  res.statusCode = proxyRes.statusCode;

  proxyRes.pipe(res);
};

// -------------------- HANDLER --------------------

export default function handler(req, res) {
  const accessKey = req.headers["proxy-access-key"];
  const target = req.headers["proxy-target"];

  if (!accessKey || !target) {
    return writeErr(res, 400, "Missing proxy-access-key or proxy-target");
  }

  const keyBuf = Buffer.from(accessKey);
  if (
    keyBuf.length !== ACCESS_KEY.length ||
    !crypto.timingSafeEqual(keyBuf, ACCESS_KEY)
  ) {
    return writeErr(res, 403, "Invalid access key");
  }

  let parsed;
  try {
    parsed = new URL(`https://${target}`);
  } catch {
    return writeErr(res, 400, "Invalid target");
  }

  const hostAllowed =
    !USE_WHITELIST ||
    ALLOWED_HOSTS.some((h) => h.host === parsed.host);

  if (!hostAllowed) {
    return writeErr(res, 400, "Host not whitelisted");
  }

  const proto =
    req.headers["proxy-target-override-proto"] || DEFAULT_PROTO;

  const proxy = proto === "https" ? httpsProxy : httpProxyServer;

  proxy.once("proxyReq", onProxyReq);
  proxy.once("proxyRes", onProxyRes);

  proxy.web(req, res, {
    target: `${proto}://${parsed.host}`
  });
}

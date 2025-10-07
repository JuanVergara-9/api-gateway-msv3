require('dotenv').config();

const express = require('express');
const compression = require('compression');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const { randomUUID } = require('crypto');
const rateLimit = require('express-rate-limit');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();
const PORT = process.env.PORT || 4000;

// ---------- Seguridad / observabilidad ----------
app.set('trust proxy', 1);

// CORS: libre en dev, whitelist en producción
const frontendOrigins = (process.env.FRONTEND_ORIGINS || '')
  .split(',').map(s => s.trim()).filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); // curl/postman
    if (process.env.NODE_ENV !== 'production') return cb(null, true);
    return cb(null, frontendOrigins.length === 0 || frontendOrigins.includes(origin));
  },
  credentials: true
}));

app.use(helmet());
app.use(compression());

app.use((req, res, next) => {
  req.id = req.headers['x-request-id'] || randomUUID();
  res.set('x-request-id', req.id);
  next();
});

app.use(morgan(':method :url :status - :response-time ms - reqId=:req[x-request-id]'));

const standardLimiter = rateLimit({ windowMs: 60_000, max: 120, standardHeaders: true, legacyHeaders: false });
const authLimiter = rateLimit({ windowMs: 60_000, max: 20, standardHeaders: true, legacyHeaders: false });
app.use(standardLimiter);

app.use((_req, res, next) => { res.setTimeout(30_000); next(); });

// ---------- Utilidad ----------
const restoreFullPath = () => (req, _res, next) => {
  req.url = req.originalUrl;
  next();
};

function safeProxy(path, envVarName, label, extraMw = []) {
  const target = process.env[envVarName];
  if (!target) {
    console.warn(`[DISABLED] ${label} (${path}) -> falta ${envVarName}`);
    app.use(path, (_req, res) =>
      res.status(503).json({ error: { code: 'GATEWAY.SERVICE_UNCONFIGURED', message: `Servicio no configurado (${label})` } })
    );
    return;
  }
  console.log(`[MOUNT] ${label}: ${path} -> ${target}`);
  app.use(
    path,
    (req, _res, next) => { console.log(`[GW][HIT] ${label} -> ${req.method} ${req.originalUrl}`); next(); },
    ...extraMw,
    createProxyMiddleware({
      target,
      changeOrigin: true,
      xfwd: true,
      proxyTimeout: 30_000,
      timeout: 30_000,
      pathRewrite: (_p, req) => req.originalUrl, // mantiene /api/v1/... completo
      onProxyReq: (proxyReq, req) => proxyReq.setHeader('x-request-id', req.id),
      onProxyRes: (proxyRes, req) => console.log(
        `[${req.id}] ${label} ${req.method} ${req.originalUrl} -> ${proxyRes.statusCode}`
      ),
      onError: (err, req, res) => {
        console.error(`[${req.id}] ${label} proxy error:`, err.code || err.message);
        if (!res.headersSent) {
          res.status(502).json({ error: { code: 'GATEWAY.BAD_GATEWAY', message: `${label} no disponible`, requestId: req.id } });
        }
      }
    })
  );
}

// ---------- Health ----------
app.get('/healthz', (_req, res) => res.json({ ok: true, service: 'api-gateway' }));

// /ready del gateway: chequea microservicios con fetch nativo + timeout
app.get('/ready', async (_req, res) => {
  const urls = [
    process.env.AUTH_SERVICE_URL,
    process.env.USER_SERVICE_URL,
    process.env.PROVIDER_SERVICE_URL,
    process.env.REVIEWS_SERVICE_URL,
    process.env.INSIGHTS_SERVICE_URL,
    process.env.GEOLOCATION_SERVICE_URL || process.env.GEO_SERVICE_URL,
    process.env.CATEGORY_SERVICE_URL
  ].filter(Boolean);

  const checks = await Promise.allSettled(
    urls.map(u => fetchWithTimeout(`${u}/readyz`, 8000).then(r => r.ok))
  );
  const ok = checks.every(c => c.status === 'fulfilled' && c.value === true);
  res.status(ok ? 200 : 503).json({ ok, services: checks.map(c => c.status) });
});

function fetchWithTimeout(url, ms) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  return fetch(url, { signal: ctrl.signal }).finally(() => clearTimeout(t));
}

// ---------- Montaje servicios ----------
safeProxy('/api/v1/auth', 'AUTH_SERVICE_URL', 'AUTH', [authLimiter]);
safeProxy('/api/v1/users', 'USER_SERVICE_URL', 'USERS');
safeProxy('/api/v1/reviews', 'REVIEWS_SERVICE_URL', 'REVIEWS');
safeProxy('/api/v1/contact-intents', 'REVIEWS_SERVICE_URL', 'REVIEWS-CI');
safeProxy('/api/v1/events', 'INSIGHTS_SERVICE_URL', 'INSIGHTS');
safeProxy('/api/v1/metrics', 'INSIGHTS_SERVICE_URL', 'INSIGHTS-METRICS');

// Geolocalización (admite 2 nombres de env)
process.env.GEOLOCATION_SERVICE_URL = process.env.GEOLOCATION_SERVICE_URL || process.env.GEO_SERVICE_URL;
safeProxy('/api/v1/geo', 'GEOLOCATION_SERVICE_URL', 'GEO');

// Rutas específicas
app.use(
  '/api/v1/user-profile',
  (req, _res, next) => { console.log(`[GW][HIT] user-profile -> ${req.method} ${req.originalUrl}`); next(); },
  restoreFullPath(),
  createProxyMiddleware({
    target: process.env.USER_SERVICE_URL,
    changeOrigin: true,
    xfwd: true,
    proxyTimeout: 30_000,
    timeout: 30_000,
    pathRewrite: { '^/api/v1/user-profile': '/api/v1/users' },
    onProxyReq: (proxyReq, req) => proxyReq.setHeader('x-request-id', req.id || 'n/a'),
    onProxyRes: (proxyRes, req) => console.log(
      `[${req.id}] USER-PROFILE ${req.method} ${req.originalUrl} -> ${proxyRes.statusCode}`
    ),
    onError: (err, req, res) => {
      console.error(`[${req.id}] USER-PROFILE proxy error:`, err.code || err.message);
      if (!res.headersSent) res.status(502).json({
        error:{ code:'GATEWAY.BAD_GATEWAY', message:'User service no disponible', requestId:req.id }
      });
    }
  })
);

app.use(
  '/api/v1/providers',
  (req, res, next) => {
    console.log(`[GW][HIT] providers -> ${req.method} url=${req.url} originalUrl=${req.originalUrl}`);
    if (req.method === 'GET') res.set('Cache-Control', 'public, max-age=30');
    next();
  },
  createProxyMiddleware({
    target: process.env.PROVIDER_SERVICE_URL,
    router: (req) => {
      const isReviewsPath = /^\/(?:api\/v1\/)?providers\/\d+\/(?:reviews|review-summary)(?:[\/?]|$)/.test(req.originalUrl);
      if (isReviewsPath && process.env.REVIEWS_SERVICE_URL) return process.env.REVIEWS_SERVICE_URL;
      return process.env.PROVIDER_SERVICE_URL;
    },
    changeOrigin: true,
    xfwd: true,
    proxyTimeout: 30_000,
    timeout: 30_000,
    pathRewrite: (_path, req) => req.originalUrl,
    onProxyReq: (proxyReq, req) => proxyReq.setHeader('x-request-id', req.id || 'n/a'),
    onProxyRes: (proxyRes, req) => console.log(
      `[${req.id}] PROVIDERS ${req.method} ${req.originalUrl} -> ${proxyRes.statusCode}`
    ),
    onError: (err, req, res) => {
      console.error(`[${req.id}] PROVIDERS proxy error:`, err.code || err.message);
      if (!res.headersSent) {
        res.status(502).json({ error: { code: 'GATEWAY.BAD_GATEWAY', message: 'Providers no disponible', requestId: req.id } });
      }
    }
  })
);

app.use(
  '/api/v1/categories',
  (req, res, next) => {
    console.log(`[GW][HIT] categories -> ${req.method} url=${req.url} originalUrl=${req.originalUrl}`);
    if (req.method === 'GET') res.set('Cache-Control', 'public, max-age=60');
    next();
  },
  createProxyMiddleware({
    target: process.env.PROVIDER_SERVICE_URL, // cambiar a CATEGORY_SERVICE_URL cuando lo separes
    changeOrigin: true,
    xfwd: true,
    proxyTimeout: 30_000,
    timeout: 30_000,
    pathRewrite: (_path, req) => req.originalUrl,
    onProxyReq: (proxyReq, req) => proxyReq.setHeader('x-request-id', req.id || 'n/a'),
    onProxyRes: (proxyRes, req) => console.log(
      `[${req.id}] CATEGORIES ${req.method} ${req.originalUrl} -> ${proxyRes.statusCode}`
    ),
    onError: (err, req, res) => {
      console.error(`[${req.id}] CATEGORIES proxy error:`, err.code || err.message);
      if (!res.headersSent) {
        res.status(502).json({ error: { code: 'GATEWAY.BAD_GATEWAY', message: 'Categories no disponible', requestId: req.id } });
      }
    }
  })
);

// ---------- 404 ----------
app.use((_req, res) => {
  res.status(404).json({ error: { code: 'GATEWAY.NOT_FOUND', message: 'Ruta no encontrada' } });
});

// Bind 0.0.0.0 para Railway
app.listen(PORT, '0.0.0.0', () => console.log(`api-gateway on :${PORT}`));

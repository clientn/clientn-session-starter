import { readFileSync } from 'node:fs';

// Tiny .env loader (no dependency). Real environment variables win over the file.
try {
  for (const line of readFileSync(new URL('../.env', import.meta.url), 'utf8').split('\n')) {
    const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/.exec(line);
    if (m && !line.trim().startsWith('#') && process.env[m[1]] === undefined) process.env[m[1]] = m[2];
  }
} catch { /* no .env file: fine */ }

export function loadConfig(env = process.env) {
  const cfg = {
    apiBase: (env.CLIENTN_API_BASE || 'https://clientn.com').replace(/\/+$/, ''),
    apiKey: env.CLIENTN_API_KEY || '',
    apiSecret: env.CLIENTN_API_SECRET || '',
    appOrigin: (env.APP_ORIGIN || 'http://localhost:3000').replace(/\/+$/, ''),
    port: Number(env.PORT || 3000),
    dbPath: env.DB_PATH || './data/app.sqlite',
  };
  cfg.secureCookies = cfg.appOrigin.startsWith('https://');
  return cfg;
}

export function assertConfig(cfg) {
  if (!/^[a-f0-9]{32}$/.test(cfg.apiKey)) throw new Error('CLIENTN_API_KEY must be the 32-character hex key from /dev');
  if (typeof cfg.apiSecret !== 'string' || cfg.apiSecret.length < 32) throw new Error('CLIENTN_API_SECRET is missing or too short');
}

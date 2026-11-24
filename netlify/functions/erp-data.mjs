import { getStore } from '@netlify/blobs';
import { scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCallback);

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store'
    }
  });

function decodeHash(value) {
  const parts = String(value || '').split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return null;
  const [, n, r, p, saltText, hashText] = parts;
  const salt = Buffer.from(saltText, 'base64url');
  const expected = Buffer.from(hashText, 'base64url');
  const N = Number(n), R = Number(r), P = Number(p);
  if (!Number.isInteger(N) || !Number.isInteger(R) || !Number.isInteger(P) ||
      N < 2 || R < 1 || P < 1 || salt.length < 16 || expected.length !== 32) return null;
  return { N, R, P, salt, expected };
}

async function isAuthorized(request) {
  const header = request.headers.get('authorization') || '';
  const storedHash = process.env.ERP_ADMIN_PASSWORD_HASH;
  if (!header.startsWith('Basic ') || !storedHash) return false;

  try {
    const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
    const separator = decoded.indexOf(':');
    if (separator < 0) return false;
    const username = decoded.slice(0, separator);
    const password = decoded.slice(separator + 1);
    if (username !== 'admin' || !password) return false;

    const parsed = decodeHash(storedHash);
    if (!parsed) return false;
    const actual = await scrypt(password, parsed.salt, parsed.expected.length, {
      N: parsed.N, r: parsed.R, p: parsed.P, maxmem: 64 * 1024 * 1024
    });
    return timingSafeEqual(actual, parsed.expected);
  } catch {
    return false;
  }
}

export default async (request) => {
  if (!['GET', 'POST'].includes(request.method)) {
    return json({ error: 'Method not allowed' }, 405);
  }

  if (!(await isAuthorized(request))) {
    return json({ error: 'Unauthorized' }, 401);
  }

  try {
    const store = getStore({
      name: 'hieuthinh-erp-workspace',
      consistency: 'strong'
    });

    if (request.method === 'GET') {
      const record = await store.get('main', { type: 'json' });
      return json({ ok: true, record: record || null });
    }

    const payload = await request.json();
    if (!payload?.data || typeof payload.data !== 'object' || Array.isArray(payload.data)) {
      return json({ error: 'Invalid ERP data' }, 400);
    }

    const current = await store.get('main', { type: 'json' });
    const incomingTime = Date.parse(payload.updatedAt || '');
    const currentTime = Date.parse(current?.updatedAt || '');
    if (current && Number.isFinite(incomingTime) && Number.isFinite(currentTime) && incomingTime < currentTime) {
      return json({ ok: false, conflict: true, record: current }, 409);
    }

    if (current) {
      await store.setJSON(`backup-${Date.now()}`, current);
    }

    const record = {
      data: payload.data,
      updatedAt: new Date().toISOString(),
      updatedBy: 'admin'
    };
    await store.setJSON('main', record);
    return json({ ok: true, record });
  } catch (error) {
    console.error('ERP data function error:', error);
    return json({ error: 'Netlify storage error' }, 500);
  }
};

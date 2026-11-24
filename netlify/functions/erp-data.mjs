
import { getStore } from '@netlify/blobs';

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store'
    }
  });

function isAuthorized(request) {
  const header = request.headers.get('authorization') || '';
  if (!header.startsWith('Basic ')) return false;

  try {
    const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
    const separator = decoded.indexOf(':');
    const username = decoded.slice(0, separator);
    const password = decoded.slice(separator + 1);
    return username === 'admin' &&
      !!process.env.ERP_ADMIN_PASSWORD &&
      password === process.env.ERP_ADMIN_PASSWORD;
  } catch {
    return false;
  }
}

export default async (request) => {
  if (!['GET', 'POST'].includes(request.method)) {
    return json({ error: 'Method not allowed' }, 405);
  }

  if (!isAuthorized(request)) {
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

    if (current && Date.parse(payload.updatedAt || '') < Date.parse(current.updatedAt || '')) {
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
    console.error(error);
    return json({ error: 'Netlify storage error' }, 500);
  }
};

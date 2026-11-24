
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
    const expected = process.env.ERP_ADMIN_PASSWORD;

    return username === 'admin' &&
      !!expected &&
      password === expected;
  } catch {
    return false;
  }
}

export default async (request) => {
  if (!['GET', 'POST'].includes(request.method)) {
    return json({ error: 'Method not allowed' }, 405);
  }

  if (!isAuthorized(request)) {
    return json({ error: 'Sai tài khoản hoặc mật khẩu ERP.' }, 401);
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

    if (
      !payload ||
      typeof payload.data !== 'object' ||
      !payload.data ||
      Array.isArray(payload.data)
    ) {
      return json({ error: 'Dữ liệu ERP không hợp lệ.' }, 400);
    }

    const current = await store.get('main', { type: 'json' });
    const incomingTime = Date.parse(payload.updatedAt || '') || Date.now();
    const currentTime = Date.parse(current?.updatedAt || '') || 0;

    if (current && incomingTime < currentTime) {
      return json({
        ok: false,
        conflict: true,
        record: current,
        error: 'Dữ liệu máy chủ mới hơn. Đã giữ nguyên dữ liệu máy chủ.'
      }, 409);
    }

    if (current) {
      const backupKey = `backup-${Date.now()}-${crypto.randomUUID()}`;
      await store.setJSON(backupKey, current);
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
    return json({
      error: 'Không thể truy cập kho dữ liệu Netlify.'
    }, 500);
  }
};

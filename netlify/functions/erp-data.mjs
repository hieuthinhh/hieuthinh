
import { getStore } from '@netlify/blobs';

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Cache-Control': 'no-store'
};

const response = (statusCode, body) => ({
  statusCode,
  headers: {
    ...cors,
    'Content-Type': 'application/json; charset=utf-8'
  },
  body: JSON.stringify(body)
});

function authorized(event) {
  const h = event.headers?.authorization ||
            event.headers?.Authorization || '';

  if (!h.startsWith('Basic ')) return false;

  try {
    const [user, ...parts] = Buffer
      .from(h.slice(6), 'base64')
      .toString('utf8')
      .split(':');

    const pass = parts.join(':');

    return user === 'admin' &&
      !!process.env.ERP_ADMIN_PASSWORD &&
      pass === process.env.ERP_ADMIN_PASSWORD;
  } catch {
    return false;
  }
}

export default async (event) => {
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: cors, body: '' };
  }

  if (!['GET', 'POST'].includes(event.httpMethod)) {
    return response(405, { error: 'Method not allowed' });
  }

  if (!authorized(event)) {
    return response(401, {
      error: 'Sai tài khoản hoặc mật khẩu ERP.'
    });
  }

  try {
    const store = getStore({
      name: 'hieuthinh-erp-workspace',
      consistency: 'strong'
    });

    if (event.httpMethod === 'GET') {
      const record = await store.get('main', { type: 'json' });
      return response(200, { ok: true, record: record || null });
    }

    const payload = JSON.parse(event.body || '{}');

    if (
      !payload ||
      typeof payload.data !== 'object' ||
      !payload.data ||
      Array.isArray(payload.data)
    ) {
      return response(400, {
        error: 'Dữ liệu ERP không hợp lệ.'
      });
    }

    const current = await store.get('main', { type: 'json' });
    const incomingTime = Date.parse(payload.updatedAt || '') || Date.now();
    const currentTime = Date.parse(current?.updatedAt || '') || 0;

    if (current && incomingTime < currentTime) {
      return response(409, {
        ok: false,
        conflict: true,
        record: current,
        error: 'Dữ liệu trên máy chủ mới hơn. Đã giữ nguyên dữ liệu máy chủ.'
      });
    }

    if (current) {
      const backupKey = `backup-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      await store.setJSON(backupKey, current);
    }

    const record = {
      data: payload.data,
      updatedAt: new Date().toISOString(),
      updatedBy: 'admin'
    };

    await store.setJSON('main', record);

    return response(200, { ok: true, record });
  } catch (error) {
    console.error('ERP data function error:', error);

    return response(500, {
      error: 'Không thể truy cập kho dữ liệu Netlify.'
    });
  }
};

/**
 * Vercel Serverless — OCR API Proxy
 * POST /api/ocr  →  腾讯云 RecognizeTableAccurateOCR  →  结构化表格 JSON
 *
 * 环境变量（在 Vercel 控制台设置）:
 *   TENCENTCLOUD_SECRET_ID
 *   TENCENTCLOUD_SECRET_KEY
 */

const crypto = require('crypto');

// ── TC3-HMAC-SHA256 签名 ──────────────────────────────────
function sha256(data, key) {
  const hmac = crypto.createHmac('sha256', key);
  hmac.update(data);
  return hmac.digest();
}

function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function signV3(secretId, secretKey, service, host, action, version, payload, region = 'ap-guangzhou') {
  const timestamp = Math.floor(Date.now() / 1000);
  const date = new Date(timestamp * 1000).toISOString().slice(0, 10).replace(/-/g, '-');
  const algorithm = 'TC3-HMAC-SHA256';

  // Step 1: Canonical Request
  const httpMethod = 'POST';
  const canonicalUri = '/';
  const canonicalQueryString = '';
  const ct = 'application/json; charset=utf-8';
  const canonicalHeaders = `content-type:${ct}\nhost:${host}\nx-tc-action:${action.toLowerCase()}\n`;
  const signedHeaders = 'content-type;host;x-tc-action';
  const hashedPayload = sha256Hex(payload);
  const canonicalRequest = [httpMethod, canonicalUri, canonicalQueryString, canonicalHeaders, signedHeaders, hashedPayload].join('\n');

  // Step 2: String to Sign
  const credentialScope = `${date}/${service}/tc3_request`;
  const hashedCanonical = sha256Hex(canonicalRequest);
  const stringToSign = [algorithm, timestamp, credentialScope, hashedCanonical].join('\n');

  // Step 3: Signature
  const secretDate = sha256(date, `TC3${secretKey}`);
  const secretService = sha256(service, secretDate);
  const secretSigning = sha256('tc3_request', secretService);
  const signature = sha256(stringToSign, secretSigning).toString('hex');

  // Step 4: Authorization
  const authorization = `${algorithm} Credential=${secretId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  return { authorization, timestamp, host };
}

// ── 调用腾讯云 OCR API ──────────────────────────────────
async function callTencentCloudOCR(imageBase64) {
  const secretId = process.env.TENCENTCLOUD_SECRET_ID;
  const secretKey = process.env.TENCENTCLOUD_SECRET_KEY;
  if (!secretId || !secretKey) throw new Error('缺少腾讯云 API 密钥，请设置 TENCENTCLOUD_SECRET_ID 和 TENCENTCLOUD_SECRET_KEY 环境变量');

  const service = 'ocr';
  const host = 'ocr.tencentcloudapi.com';
  const action = 'RecognizeTableAccurateOCR';
  const version = '2018-11-19';
  const region = 'ap-guangzhou';
  const payload = JSON.stringify({ ImageBase64: imageBase64 });

  const { authorization, timestamp } = signV3(secretId, secretKey, service, host, action, version, payload, region);

  const url = `https://${host}`;
  const resp = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': authorization,
      'Content-Type': 'application/json; charset=utf-8',
      'Host': host,
      'X-TC-Action': action,
      'X-TC-Timestamp': String(timestamp),
      'X-TC-Version': version,
      'X-TC-Region': region,
    },
    body: payload,
  });

  const data = await resp.json();
  if (data.Response.Error) {
    throw new Error(`腾讯云 API 错误: ${data.Response.Error.Code} — ${data.Response.Error.Message}`);
  }
  return data.Response;
}

// ── 腾讯云原始响应 → 工作台 JSON 格式 ──────────────────
function convertToWorkbenchFormat(response) {
  const tables = response.TableDetections || [];
  if (!tables.length) return { headers: [], rows: [], meta: { tables: 0 } };

  const allTables = tables.map((table, ti) => {
    const cells = table.Cells || [];
    if (!cells.length) return { headers: [], rows: [] };

    // Build grid from cell coordinates
    const grid = {};
    let maxRow = 0, maxCol = 0;
    cells.forEach(c => {
      for (let r = c.RowTl; r <= c.RowBr; r++) {
        for (let col = c.ColTl; col <= c.ColBr; col++) {
          const key = `${r}_${col}`;
          if (!grid[key]) grid[key] = { text: [], confidences: [], type: c.Type };
          grid[key].text.push(c.Text);
          grid[key].confidences.push(c.Confidence);
          if (r > maxRow) maxRow = r;
          if (col > maxCol) maxCol = col;
        }
      }
    });

    // Build matrix
    const matrix = [];
    for (let r = 0; r <= maxRow; r++) {
      const row = [];
      for (let c = 0; c <= maxCol; c++) {
        const key = `${r}_${c}`;
        const cell = grid[key];
        if (cell) {
          const avgConf = cell.confidences.reduce((a, b) => a + b, 0) / cell.confidences.length;
          row.push({ text: cell.text.join(' '), confidence: Math.round(avgConf) });
        } else {
          row.push({ text: '', confidence: 0 });
        }
      }
      matrix.push(row);
    }

    const headers = matrix[0]?.map(c => c.text) || [];
    const rows = matrix.slice(1).map(row => row.map(c => {
      // If confidence < 50, mark with warning
      return c.confidence < 50 ? `${c.text} [低置信度:${c.confidence}%]` : c.text;
    }));

    return { headers, rows, type: table.Type };
  });

  // Merge all tables (most cases just one)
  const mergedHeaders = allTables[0].headers;
  const mergedRows = allTables.flatMap(t => t.rows);
  const typeMap = { 0: '非表格文本', 1: '有线表格', 2: '无线表格' };

  return {
    headers: mergedHeaders,
    rows: mergedRows,
    meta: {
      tables: allTables.length,
      types: allTables.map(t => typeMap[t.type] || '未知'),
      angle: response.Angle || 0,
      requestId: response.RequestId || '',
    },
  };
}

// ── Vercel Serverless Handler ──────────────────────────────────
module.exports = async function handler(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  if (req.method !== 'POST') {
    res.status(405).json({ error: '仅支持 POST 请求' });
    return;
  }

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    const { imageBase64 } = body || {};

    if (!imageBase64) {
      res.status(400).json({ error: '缺少 imageBase64 参数' });
      return;
    }

    // Strip data:image prefix if present
    const cleanBase64 = imageBase64.replace(/^data:image\/\w+;base64,/, '');

    const ocrResult = await callTencentCloudOCR(cleanBase64);
    const formatted = convertToWorkbenchFormat(ocrResult);

    res.status(200).json(formatted);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

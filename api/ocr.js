/**
 * Vercel Serverless — Tencent Cloud RecognizeTableAccurateOCR 代理
 * 接收前端传来的图片+密钥，完成 TC3-HMAC-SHA256 签名后代理调用腾讯云 API。
 * 密钥优先级：请求体中的 SecretId/SecretKey > 环境变量
 */

const crypto = require('crypto');

function sha256Hex(data) {
  return crypto.createHash('sha256').update(data, 'utf8').digest('hex');
}

function hmacSha256(key, data) {
  return crypto.createHmac('sha256', key).update(data, 'utf8').digest();
}

/**
 * TC3-HMAC-SHA256 签名
 * @see https://cloud.tencent.com/document/api/866/33518
 */
function tc3Sign(secretId, secretKey, service, host, action, version, region, payload) {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const date = new Date(parseInt(timestamp) * 1000).toISOString().slice(0, 10);

  // 1. CanonicalRequest
  const httpRequestMethod = 'POST';
  const canonicalUri = '/';
  const canonicalQueryString = '';
  const canonicalHeaders = `content-type:application/json; charset=utf-8\nhost:${host}\nx-tc-action:${action.toLowerCase()}\n`;
  const signedHeaders = 'content-type;host;x-tc-action';
  const hashedRequestPayload = sha256Hex(payload);
  const canonicalRequest = [
    httpRequestMethod,
    canonicalUri,
    canonicalQueryString,
    canonicalHeaders,
    signedHeaders,
    hashedRequestPayload,
  ].join('\n');

  // 2. StringToSign
  const algorithm = 'TC3-HMAC-SHA256';
  const credentialScope = `${date}/${service}/tc3_request`;
  const hashedCanonicalRequest = sha256Hex(canonicalRequest);
  const stringToSign = [algorithm, timestamp, credentialScope, hashedCanonicalRequest].join('\n');

  // 3. Signature
  const kDate = hmacSha256('TC3' + secretKey, date);
  const kService = hmacSha256(kDate, service);
  const kSigning = hmacSha256(kService, 'tc3_request');
  const signature = hmacSha256(kSigning, stringToSign).toString('hex');

  // 4. Authorization
  const authorization = `${algorithm} Credential=${secretId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  return { authorization, timestamp };
}

/**
 * 解析腾讯云 OCR 返回的表格数据
 */
function parseOCRResult(json) {
  const resp = json.Response;
  if (resp.Error) throw new Error(`[${resp.Error.Code}] ${resp.Error.Message}`);

  const tableDetections = resp.TableDetections || [];
  const allRows = [];
  let headers = [];

  for (const table of tableDetections) {
    const cells = table.Cells || [];
    if (!cells.length) continue;

    // 找出最大行/列索引
    let maxRow = 0, maxCol = 0;
    const cellMap = new Map();
    for (const cell of cells) {
      const r = cell.RowTl || cell.Row || 0;
      const c = cell.ColTl || cell.Col || 0;
      maxRow = Math.max(maxRow, r);
      maxCol = Math.max(maxCol, c);
      cellMap.set(`${r},${c}`, cell.Text || '');
    }

    // 重建表格
    const tableRows = [];
    for (let r = 0; r <= maxRow; r++) {
      const row = [];
      for (let c = 0; c <= maxCol; c++) {
        row.push(cellMap.get(`${r},${c}`) || '');
      }
      tableRows.push(row);
    }

    if (!headers.length && tableRows.length) {
      headers = tableRows[0];
    }
    allRows.push(...(headers.length && tableRows.length > 1 ? tableRows.slice(1) : tableRows));
  }

  return {
    headers: headers.length ? headers : [],
    rows: allRows,
    meta: {
      tableCount: tableDetections.length,
      totalCells: resp.CellCount || 0,
      angle: resp.Angle || 0,
    },
  };
}

// ── API Handler ──
export default async function handler(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }

  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  try {
    const { ImageBase64, SecretId, SecretKey, LanguageType } = req.body;

    if (!ImageBase64) {
      res.status(400).json({ error: '缺少 ImageBase64' });
      return;
    }

    // 密钥优先级：请求体 > 环境变量
    const secretId = SecretId || process.env.TENCENTCLOUD_SECRET_ID;
    const secretKey = SecretKey || process.env.TENCENTCLOUD_SECRET_KEY;

    if (!secretId || !secretKey) {
      res.status(400).json({ error: '请在页面配置腾讯云 API 密钥，或在 Vercel 设置环境变量 TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY' });
      return;
    }

    const service = 'ocr';
    const host = 'ocr.tencentcloudapi.com';
    const action = 'RecognizeTableAccurateOCR';
    const version = '2018-11-19';
    const region = '';

    // 去掉 base64 前缀（若有）
    const pureBase64 = ImageBase64.replace(/^data:image\/\w+;base64,/, '');

    const payload = JSON.stringify({
      ImageBase64: pureBase64,
      ...(LanguageType ? { LanguageType } : {}),
    });

    const { authorization, timestamp } = tc3Sign(secretId, secretKey, service, host, action, version, region, payload);

    const resp = await fetch(`https://${host}`, {
      method: 'POST',
      headers: {
        'Authorization': authorization,
        'Content-Type': 'application/json; charset=utf-8',
        'Host': host,
        'X-TC-Action': action,
        'X-TC-Timestamp': timestamp,
        'X-TC-Version': version,
      },
      body: payload,
    });

    const json = await resp.json();
    const result = parseOCRResult(json);

    res.status(200).json(result);
  } catch (err) {
    console.error('OCR proxy error:', err);
    res.status(500).json({ error: err.message || 'OCR 识别失败' });
  }
}

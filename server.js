/**
 * 本地开发服务器 — 前端 + OCR API 一体化
 * 用法: node server.js  →  浏览器打开 http://localhost:3000
 *
 * 需要环境变量:
 *   TENCENTCLOUD_SECRET_ID=xxx
 *   TENCENTCLOUD_SECRET_KEY=xxx
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

// ── TC3-HMAC-SHA256 签名 ──────────────────────────────────
function sha256(data, key) {
  return crypto.createHmac('sha256', key).update(data).digest();
}
function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}
function signV3(secretId, secretKey, service, host, action, version, payload, region) {
  const timestamp = Math.floor(Date.now() / 1000);
  const date = new Date(timestamp * 1000).toISOString().slice(0, 10);
  const ct = 'application/json; charset=utf-8';
  const canonicalHeaders = `content-type:${ct}\nhost:${host}\nx-tc-action:${action.toLowerCase()}\n`;
  const signedHeaders = 'content-type;host;x-tc-action';
  const canonicalRequest = ['POST', '/', '', canonicalHeaders, signedHeaders, sha256Hex(payload)].join('\n');
  const credentialScope = `${date}/${service}/tc3_request`;
  const stringToSign = ['TC3-HMAC-SHA256', timestamp, credentialScope, sha256Hex(canonicalRequest)].join('\n');
  const secretDate = sha256(date, `TC3${secretKey}`);
  const secretService = sha256(service, secretDate);
  const secretSigning = sha256('tc3_request', secretService);
  const signature = sha256(stringToSign, secretSigning).toString('hex');
  const authorization = `TC3-HMAC-SHA256 Credential=${secretId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return { authorization, timestamp };
}

// ── 调用腾讯云 OCR ──────────────────────────────────
async function callTencentCloudOCR(imageBase64) {
  const secretId = process.env.TENCENTCLOUD_SECRET_ID;
  const secretKey = process.env.TENCENTCLOUD_SECRET_KEY;
  if (!secretId || !secretKey) throw new Error('缺少腾讯云密钥。设置环境变量: TENCENTCLOUD_SECRET_ID, TENCENTCLOUD_SECRET_KEY');

  const service = 'ocr';
  const host = 'ocr.tencentcloudapi.com';
  const action = 'RecognizeTableAccurateOCR';
  const version = '2018-11-19';
  const region = 'ap-guangzhou';
  const payload = JSON.stringify({ ImageBase64: imageBase64 });
  const { authorization, timestamp } = signV3(secretId, secretKey, service, host, action, version, payload, region);
  const contentType = 'application/json; charset=utf-8';

  const resp = await fetch(`https://${host}`, {
    method: 'POST',
    headers: {
      'Authorization': authorization,
      'Content-Type': contentType,
      'Host': host,
      'X-TC-Action': action,
      'X-TC-Timestamp': String(timestamp),
      'X-TC-Version': version,
      'X-TC-Region': region,
    },
    body: payload,
  });
  const data = await resp.json();
  if (data.Response?.Error) throw new Error(`腾讯云错误: ${data.Response.Error.Code} — ${data.Response.Error.Message}`);
  return data.Response;
}

// ── OCR 结果 → 表格格式 ──────────────────────────────────
function convertToWorkbenchFormat(response) {
  const tables = response.TableDetections || [];
  if (!tables.length) return { headers: [], rows: [], meta: { tables: 0 } };

  const allTables = tables.map((table) => {
    const cells = table.Cells || [];
    if (!cells.length) return { headers: [], rows: [] };
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
    const matrix = [];
    for (let r = 0; r <= maxRow; r++) {
      const row = [];
      for (let c = 0; c <= maxCol; c++) {
        const cell = grid[`${r}_${c}`];
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
    const rows = matrix.slice(1).map(row => row.map(c =>
      c.confidence < 50 ? `${c.text} [低置信度:${c.confidence}%]` : c.text
    ));
    return { headers, rows, type: table.Type };
  });

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

// ── HTTP Server ──────────────────────────────────
const server = http.createServer(async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }

  // API: /api/ocr
  if (req.url === '/api/ocr' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const { imageBase64 } = JSON.parse(body);
        if (!imageBase64) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: '缺少 imageBase64' })); return; }
        const clean = imageBase64.replace(/^data:image\/\w+;base64,/, '');
        const result = await callTencentCloudOCR(clean);
        const formatted = convertToWorkbenchFormat(result);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(formatted));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // 静态文件
  let filePath = req.url === '/' ? '/index.html' : req.url;
  filePath = path.join(__dirname, filePath.split('?')[0]);
  const ext = path.extname(filePath);
  if (!MIME[ext]) { res.writeHead(404); res.end('Not Found'); return; }
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not Found'); return; }
    res.writeHead(200, { 'Content-Type': MIME[ext] });
    res.end(data);
  });
});

server.listen(PORT, () => {
  const hasKeys = process.env.TENCENTCLOUD_SECRET_ID && process.env.TENCENTCLOUD_SECRET_KEY;
  console.log('\n  ┌──────────────────────────────────────────────┐');
  console.log('  │         OCR Workbench v2.0                  │');
  console.log('  ├──────────────────────────────────────────────┤');
  console.log(`  │  地址: http://localhost:${PORT}                  │`);
  console.log(`  │  引擎: 腾讯云表格识别 v3                      │`);
  console.log(`  │  密钥: ${hasKeys ? '✅ 已配置' : '❌ 未配置 (OCR不可用)'}                │`);
  console.log('  └──────────────────────────────────────────────┘\n');
  if (!hasKeys) {
    console.log('  ⚠️  未检测到腾讯云密钥，请设置环境变量后重启：\n');
    console.log('  Windows PowerShell:');
    console.log('    $env:TENCENTCLOUD_SECRET_ID="你的SecretId"');
    console.log('    $env:TENCENTCLOUD_SECRET_KEY="你的SecretKey"');
    console.log('    node server.js\n');
    console.log('  或在腾讯云控制台获取: https://console.cloud.tencent.com/cam/capi\n');
  }
});

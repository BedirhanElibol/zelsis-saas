const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 3030;
const FILE_PATH = path.join('C:', 'Users', 'Bedirhan', 'Desktop', 'school', 'public', 'landing-page.html');

const server = http.createServer((req, res) => {
  fs.readFile(FILE_PATH, (err, data) => {
    if (err) {
      res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Dosya okuma hatası: ' + err.message);
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(data);
  });
});

server.listen(PORT, () => {
  console.log(`CareLog Landing Page Sunucusu Çalışıyor: http://localhost:${PORT}`);
});

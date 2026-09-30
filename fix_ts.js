const fs = require('fs');
let p = 'app/api/v1/gate-check/route.ts';
let c = fs.readFileSync(p, 'utf8');
c = c.replace(/const body = await request.json\(\);/g, 'const body = (await request.json()) as any;');
fs.writeFileSync(p, c);

p = 'lib/validations/api-schemas.ts';
c = fs.readFileSync(p, 'utf8');
c = c.replace(/required_error/g, 'message');
c = c.replace(/\.errors/g, '.issues');
fs.writeFileSync(p, c);

p = 'tailwind.config.ts';
c = fs.readFileSync(p, 'utf8');
c = c.replace(/darkMode: \['class'\],/g, 'darkMode: \'class\',');
c = c.replace(/darkMode: \[\"class\"\],/g, 'darkMode: \"class\",');
fs.writeFileSync(p, c);

const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

const projectDir = path.resolve(__dirname, '../../');
const ignoreDirs = ['.git', 'node_modules', 'reports', '.vscode', '.agent'];
const ignoreFiles = ['.idea_history.json', 'package-lock.json'];

let timeoutId = null;
let isPushing = false;
let pendingChanges = false;

function runCommand(cmd) {
    return new Promise((resolve) => {
        exec(cmd, { cwd: projectDir }, (error, stdout, stderr) => {
            if (error) {
                console.error(`[Error] Komut başarısız: ${cmd}\n`, stderr || error.message);
                return resolve(null);
            }
            resolve(stdout.trim());
        });
    });
}

async function autoPush() {
    if (isPushing) {
        pendingChanges = true;
        return;
    }
    
    isPushing = true;
    pendingChanges = false;
    
    console.log(`\n[Watcher] [${new Date().toLocaleTimeString('tr-TR')}] Değişiklikler detected, yükleme başlatılıyor...`);
    
    const status = await runCommand('git status --porcelain');
    if (status === null) {
        isPushing = false;
        return;
    }
    
    if (status === '') {
        console.log('[Watcher] Commit edilecek değişiklik bulunamadı.');
        isPushing = false;
        return;
    }
    
    console.log('[Watcher] Dosyalar ekleniyor (git add)...');
    await runCommand('git add .');
    
    const commitMsg = `auto: update codebase at ${new Date().toLocaleString('tr-TR')}`;
    console.log(`[Watcher] Değişiklikler kaydediliyor (git commit)...`);
    await runCommand(`git commit -m "${commitMsg}"`);
    
    console.log('[Watcher] GitHub\'a yükleniyor (git push)...');
    const pushOutput = await runCommand('git push origin main');
    
    if (pushOutput !== null) {
        console.log('[Watcher] Güncellemeler başarıyla GitHub\'a yüklendi! 🚀');
    } else {
        console.error('[Watcher] GitHub\'a yükleme sırasında hata oluştu.');
    }
    
    isPushing = false;
    if (pendingChanges) {
        autoPush();
    }
}

function handleChange(eventType, filename) {
    if (!filename) return;
    
    // Ignore patterns
    const relativePath = path.normalize(filename);
    const parts = relativePath.split(path.sep);
    
    if (parts.some(part => ignoreDirs.includes(part))) return;
    if (ignoreFiles.includes(path.basename(filename))) return;
    
    console.log(`[Watcher] Değişiklik detected: ${filename} (${eventType})`);
    
    // Debounce to prevent multiple quick triggers (5 seconds window)
    if (timeoutId) clearTimeout(timeoutId);
    timeoutId = setTimeout(autoPush, 5000);
}

console.log(`============================================================`);
console.log(`🔄 GITHUB OTOMATİK YÜKLEYİCİ (WATCHER) BAŞLATILDI`);
console.log(`============================================================`);
console.log(`İzlenen Dizin: ${projectDir}`);
console.log(`Yoksayılan Dizinler: ${ignoreDirs.join(', ')}`);
console.log(`Yoksayılan Dosyalar: ${ignoreFiles.join(', ')}\n`);

fs.watch(projectDir, { recursive: true }, handleChange);

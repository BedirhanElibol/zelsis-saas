const fs = require('fs');
const path = require('path');

const BASE_DIR = path.resolve(__dirname);

function assertSafePath(targetPath, baseDir = BASE_DIR) {
    const normalized = path.normalize(targetPath);
    const resolved = path.resolve(baseDir, normalized);
    const resolvedBase = path.resolve(baseDir);
    const isWindows = process.platform === 'win32';
    const checkResolved = isWindows ? resolved.toLowerCase() : resolved;
    const checkBase = isWindows ? resolvedBase.toLowerCase() : resolvedBase;
    const prefix = checkBase.endsWith(path.sep) ? checkBase : checkBase + path.sep;

    if (!checkResolved.startsWith(prefix) && checkResolved !== checkBase) {
        throw new Error(`Path traversal detected: ${targetPath}`);
    }
    return resolved;
}

function replaceInFile(filePath, search, replacement) {
    const safePath = assertSafePath(filePath);
    if (fs.existsSync(safePath)) {
        let content = fs.readFileSync(safePath, 'utf8');
        content = content.replace(search, replacement);
        fs.writeFileSync(safePath, content);
    }
}

// 1. OverviewView.tsx
replaceInFile(
    'components/OverviewView.tsx',
    'Next.js 15 SaaS Starter',
    'Production Web App'
);

// 2. ProductCapabilities.tsx
replaceInFile(
    'components/saas/ProductCapabilities.tsx',
    'Next.js 15 Server Components',
    'Next.js, Django, FastAPI & Go'
);
replaceInFile(
    'components/saas/ProductCapabilities.tsx',
    /1,?450\+/g,
    'Verified'
);

// 3. FaqSection.tsx
replaceInFile(
    'components/saas/FaqSection.tsx',
    'Next.js 15 App Router best practices',
    'Django, FastAPI, Go, and React best practices'
);

// 4. ProjectsView.tsx
replaceInFile(
    'components/ProjectsView.tsx',
    'Next.js 15 + Prisma SaaS',
    'Enterprise Backend (Django/Go)'
);

// 5. DashboardView.tsx
replaceInFile(
    'components/dashboard/DashboardView.tsx',
    "framework: p.framework || 'Next.js 15'",
    "framework: p.framework || 'Polyglot Web App'"
);

// 6. ConnectTargetModal.tsx
replaceInFile(
    'components/layout/ConnectTargetModal.tsx',
    "'Next.js 15'",
    "'Polyglot App'"
);
replaceInFile(
    'components/projects/NewProjectModal.tsx',
    "<'Next.js 15' | 'Vite + React' | 'FastAPI + React' | 'SvelteKit'>('Next.js 15')",
    "<'Next.js/React' | 'Python (Django/FastAPI)' | 'Go Microservices' | 'Mobile (React Native/Flutter)'>('Python (Django/FastAPI)')"
);

console.log("Generalized frameworks.");

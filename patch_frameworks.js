const fs = require('fs');

function replaceInFile(filePath, search, replacement) {
    if (fs.existsSync(filePath)) {
        let content = fs.readFileSync(filePath, 'utf8');
        content = content.replace(search, replacement);
        fs.writeFileSync(filePath, content);
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

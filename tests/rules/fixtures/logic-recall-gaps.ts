import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

// Shapes from the real-world bug corpus (.cache/logic-bug-corpus.txt) that the first versions of these rules missed
const f = (path: string, content: string): CodeFile[] => [{ path, content }];
const NEXT = { path: 'package.json', content: '{ "dependencies": { "next": "16.0.1", "react": "19.2.0" } }' };

export const CASES: RuleCase[] = [
  {
    ruleIds: [29744], name: 'BUG-111 namespace Dialog.Content without a title',
    detects: f('components/confirm-dialog.tsx', `import * as Dialog from '@radix-ui/react-dialog';
export function ConfirmDialog({ open }: { open: boolean }) {
  return (
    <Dialog.Root open={open}>
      <Dialog.Content className="p-4">
        <p>Confirm action?</p>
      </Dialog.Content>
    </Dialog.Root>
  );
}
`),
    ignores: f('components/confirm-dialog.tsx', `import * as Dialog from '@radix-ui/react-dialog';
export function ConfirmDialog({ open }: { open: boolean }) {
  return (
    <Dialog.Root open={open}>
      <Dialog.Content className="p-4">
        <Dialog.Title>Confirm</Dialog.Title>
        <p>Confirm action?</p>
      </Dialog.Content>
    </Dialog.Root>
  );
}
`),
  },
  {
    ruleIds: [29751], name: 'BUG-118 shadcn theme-provider wrapper without suppressHydrationWarning',
    detects: f('app/layout.tsx', `import { ThemeProvider } from '@/components/theme-provider';
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body><ThemeProvider>{children}</ThemeProvider></body>
    </html>
  );
}
`),
    ignores: f('app/layout.tsx', `import { ThemeProvider } from '@mui/material/styles';
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body><ThemeProvider theme={{}}>{children}</ThemeProvider></body>
    </html>
  );
}
`),
  },
  {
    ruleIds: [29710], name: 'BUG-100 get_db in deps.py returns the session',
    detects: f('app/deps.py', `from .database import SessionLocal


def get_db():
    db = SessionLocal()
    return db
`),
    ignores: f('app/deps.py', `from .database import SessionLocal


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
`),
  },
  {
    ruleIds: [29707], name: 'BUG-97 to_cents helper truncates',
    detects: f('billing/stripe.py', `def to_cents(dollars: float) -> int:
    return int(dollars * 100)
`),
    ignores: f('billing/stripe.py', `def to_cents(dollars: float) -> int:
    return int(round(dollars * 100))
`),
  },
  {
    ruleIds: [29611], name: 'BUG-11 module-level localStorage in a Next.js .ts module',
    detects: [NEXT, { path: 'lib/theme.ts', content: `export const savedTheme = localStorage.getItem('theme') || 'light';
export function getTheme() { return savedTheme; }
` }],
    ignores: [NEXT, { path: 'lib/theme.ts', content: `export function getTheme() {
  return typeof window === 'undefined' ? 'light' : localStorage.getItem('theme') || 'light';
}
` }],
  },
];

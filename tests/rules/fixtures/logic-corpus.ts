import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [29780], name: 'BUG-133 selector sorts store state in place',
    detects: f('components/project-list.tsx', `import { useStore } from '@/store';
export function ProjectList() {
  const sorted = useStore((s) => s.projects.sort((a, b) => a.id - b.id));
  return <div>{sorted.length}</div>;
}
`),
    ignores: f('components/project-list.tsx', `import { useStore } from '@/store';
export function ProjectList() {
  const projects = useStore((s) => s.projects);
  const sorted = [...projects].sort((a, b) => a.id - b.id);
  return <div>{sorted.length}</div>;
}
`),
  },
  {
    ruleIds: [29781], name: 'BUG-134 jotai setter called while rendering',
    detects: f('components/sync-state.tsx', `import { useSetAtom } from 'jotai';
import { countAtom } from './atoms';
export function SyncState({ count }: { count: number }) {
  const setCount = useSetAtom(countAtom);
  setCount(count);
  return <div>{count}</div>;
}
`),
    ignores: f('components/sync-state.tsx', `import { useEffect } from 'react';
import { useSetAtom } from 'jotai';
import { countAtom } from './atoms';
export function SyncState({ count }: { count: number }) {
  const setCount = useSetAtom(countAtom);
  useEffect(() => { setCount(count); }, [count, setCount]);
  return <button onClick={() => setCount(0)}>{count}</button>;
}
`),
  },
  {
    ruleIds: [29782], name: 'BUG-135 onValueChange reads e.target.value',
    detects: f('components/selector.tsx', `import { Select } from '@/components/ui/select';
export function Selector({ setVal }: { setVal: (v: string) => void }) {
  return <Select onValueChange={(e) => setVal(e.target.value)} />;
}
`),
    ignores: f('components/selector.tsx', `import { Select } from '@/components/ui/select';
export function Selector({ setVal }: { setVal: (v: string) => void }) {
  return <Select onValueChange={(value) => setVal(value)} />;
}
`),
  },
  {
    ruleIds: [29783], name: 'BUG-136 register spread onto a shadcn Switch',
    detects: f('components/switch-field.tsx', `import { Switch } from '@/components/ui/switch';
import { useForm } from 'react-hook-form';
export function SwitchField() {
  const { register } = useForm();
  return <Switch {...register('notifications')} />;
}
`),
    ignores: f('components/switch-field.tsx', `import { Switch } from '@/components/ui/switch';
import { Controller, useForm } from 'react-hook-form';
export function SwitchField() {
  const { control, register } = useForm();
  return (
    <>
      <input {...register('email')} />
      <Controller name="notifications" control={control} render={({ field }) => <Switch checked={field.value} onCheckedChange={field.onChange} />} />
    </>
  );
}
`),
  },
  {
    ruleIds: [29784], name: 'BUG-137 aria-hidden over a button',
    detects: f('components/panel.tsx', `export function Panel() {
  return (
    <div aria-hidden="true" className="panel">
      <button type="button">Close</button>
    </div>
  );
}
`),
    ignores: f('components/panel.tsx', `export function Panel() {
  return (
    <div className="panel">
      <span aria-hidden="true">×</span>
      <button type="button">Close</button>
    </div>
  );
}
`),
  },
  {
    ruleIds: [29785], name: 'BUG-138 Expo Router param used as a string',
    detects: f('app/project/[id].tsx', `import { useLocalSearchParams } from 'expo-router';
export default function ProjectScreen() {
  const { id } = useLocalSearchParams();
  const slug = id.toLowerCase();
  return null;
}
`),
    ignores: f('app/project/[id].tsx', `import { useLocalSearchParams } from 'expo-router';
export default function ProjectScreen() {
  const { id } = useLocalSearchParams<{ id: string }>();
  const slug = id.toLowerCase();
  return null;
}
`),
  },
  {
    ruleIds: [29786], name: 'BUG-139 SvelteKit action returns error without fail()',
    detects: f('src/routes/login/+page.server.ts', `export const actions = {
  default: async ({ request }) => {
    const data = await request.formData();
    if (!data.get('email')) {
      return { error: 'Email required' };
    }
  }
};
`),
    ignores: f('src/routes/login/+page.server.ts', `import { fail } from '@sveltejs/kit';
export const actions = {
  default: async ({ request }) => {
    const data = await request.formData();
    if (!data.get('email')) {
      return fail(400, { error: 'Email required' });
    }
    return { success: true };
  }
};
`),
  },
  {
    ruleIds: [29787], name: 'BUG-140 background task gets the request session',
    detects: f('routers/export.py', `from fastapi import APIRouter, BackgroundTasks, Depends

router = APIRouter()


@router.post("/export")
def export(bg: BackgroundTasks, db: Session = Depends(get_db)):
    bg.add_task(generate_csv, db)
    return {"status": "started"}
`),
    ignores: f('routers/export.py', `from fastapi import APIRouter, BackgroundTasks, Depends

router = APIRouter()


@router.post("/export")
def export(bg: BackgroundTasks, user_id: int, db: Session = Depends(get_db)):
    bg.add_task(generate_csv, user_id)
    return {"status": "started"}
`),
  },
  {
    ruleIds: [29788], name: 'BUG-141 untyped FastAPI path parameter',
    detects: f('routers/items.py', `from fastapi import APIRouter

router = APIRouter()


@router.get("/items/{item_id}")
async def read_item(item_id):
    return await db.fetch_one(select(Item).where(Item.id == item_id))
`),
    ignores: f('routers/items.py', `from fastapi import APIRouter

router = APIRouter()


@router.get("/items/{item_id}")
async def read_item(item_id: int):
    return await db.fetch_one(select(Item).where(Item.id == item_id))
`),
  },
  {
    ruleIds: [29789], name: 'BUG-142 naive now() vs aware datetimes',
    detects: f('services/auth.py', `from datetime import datetime, timedelta, timezone


def issue(token):
    token.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)


def is_expired(token):
    return datetime.now() > token.expires_at
`),
    ignores: f('services/auth.py', `from datetime import datetime, timedelta, timezone


def issue(token):
    token.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)


def is_expired(token):
    return datetime.now(timezone.utc) > token.expires_at
`),
  },
  {
    ruleIds: [29790], name: 'BUG-143 Gin error response without return',
    detects: f('handlers/auth.go', `package handlers

func HandleLogin(c *gin.Context) {
	if c.Query("token") == "" {
		c.JSON(400, gin.H{"error": "missing token"})
	}
	c.JSON(200, gin.H{"status": "ok"})
}
`),
    ignores: f('handlers/auth.go', `package handlers

func HandleLogin(c *gin.Context) {
	if c.Query("token") == "" {
		c.JSON(400, gin.H{"error": "missing token"})
		return
	}
	c.JSON(200, gin.H{"status": "ok"})
}
`),
  },
];

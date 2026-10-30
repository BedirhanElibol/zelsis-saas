import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [29604], name: 'BUG-04 effect that always sets state vs one that sets only when the value changed',
    detects: f('src/Thumb.tsx', 'import { useEffect, useState } from "react";\nexport function Thumb() {\n  const [rtl, setRtl] = useState(false);\n  useEffect(() => {\n    setRtl(getDir() === "rtl");\n  });\n  return <i data-rtl={rtl} />;\n}\n'),
    ignores: f('src/Thumb.tsx', 'import { useEffect, useState } from "react";\nexport function Thumb() {\n  const [rtl, setRtl] = useState(false);\n  useEffect(() => {\n    const next = getDir() === "rtl";\n    if (next !== rtl) setRtl(next);\n  });\n  return <i data-rtl={rtl} />;\n}\n'),
  },
  {
    ruleIds: [29604], name: 'BUG-04 effect that sets state directly vs from a listener it removes on cleanup',
    detects: f('src/Pick.tsx', 'import { useEffect, useState } from "react";\nexport function Pick() {\n  const [d, setD] = useState(0);\n  useEffect(() => {\n    setD(Date.now());\n  });\n  return <i>{d}</i>;\n}\n'),
    ignores: f('src/Pick.tsx', 'import { useEffect, useState } from "react";\nexport function Pick() {\n  const [d, setD] = useState(0);\n  useEffect(() => {\n    const reset = () => setD(0);\n    document.addEventListener("reset", reset);\n    return () => document.removeEventListener("reset", reset);\n  });\n  return <i>{d}</i>;\n}\n'),
  },
  {
    ruleIds: [16], name: 'SEC-16 joined strings with a value vs fixed strings only',
    detects: f('src/btn.ts', 'export function label(btn: HTMLElement, name: string) {\n  btn.innerHTML =\n    "<span>" +\n    name;\n}\n'),
    ignores: f('src/btn.ts', 'export function label(btn: HTMLElement) {\n  btn.innerHTML =\n    "<span>" +\n    "Stop</span>";\n}\n'),
  },
  {
    ruleIds: [29881], name: 'BUG-204 stream parser vs a data URL check beside a plain JSON response',
    detects: f('src/chat.ts', 'export async function run(res: Response) {\n  const reader = res.body!.getReader();\n  const line = await nextLine(reader);\n  if (line.startsWith("data:")) return JSON.parse(line.slice(5)).choices[0].delta.content;\n}\n'),
    ignores: f('src/speech.ts', 'const URL = "https://api.groq.com/openai/v1/audio/transcriptions";\nconst isDataUrl = (v: string) => v.startsWith("data:") && v.includes(",");\nexport const parse = (body: string) => JSON.parse(body);\n'),
  },
  {
    ruleIds: [18101], name: 'MYSQL-SEC-01 raw value in an f-string vs names that all pass through an identifier quoter',
    detects: f('app/search.py', 'def read(cursor, name):\n    cursor.execute(f"SELECT * FROM users WHERE name = {name}")\n'),
    ignores: f('app/search.py', 'def _quoted(name):\n    return \'"\' + str(name).replace(\'"\', \'""\') + \'"\'\n\ndef read(cursor, table, columns):\n    quoted = [_quoted(c) for c in columns]\n    size = " + ".join(f"length({q})" for q in quoted)\n    cursor.execute(f"SELECT {\', \'.join(quoted)} FROM {_quoted(table)} WHERE admit({size})")\n'),
  },
  {
    ruleIds: [29982], name: 'DBG-03 trigger function that updates its table vs a later function that does, unrelated to the trigger',
    detects: f('migrations/1_jobs.sql', 'CREATE FUNCTION public.touch() RETURNS trigger AS $$ BEGIN UPDATE public.jobs SET n = 1; RETURN NEW; END; $$ LANGUAGE plpgsql;\nCREATE TRIGGER jobs_touch AFTER UPDATE ON public.jobs FOR EACH ROW EXECUTE FUNCTION public.touch();\n'),
    ignores: f('migrations/1_jobs.sql', 'CREATE TRIGGER jobs_updated_at BEFORE UPDATE ON public.jobs FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();\nCREATE FUNCTION public.claim_job() RETURNS void AS $$ UPDATE public.jobs SET state = 1; $$ LANGUAGE sql;\n'),
  },
  {
    ruleIds: [16], name: 'SEC-16 user value in innerHTML vs markup built only from constants',
    detects: f('src/rail.ts', 'export function show(rail: HTMLElement, title: string) {\n  rail.innerHTML = `\n    <div id="${RAIL_ID}">${title}</div>\n  `;\n}\n'),
    ignores: f('src/rail.ts', 'export function show(rail: HTMLElement) {\n  rail.innerHTML = `\n    <div id="${RAIL_ID}"></div>\n  `;\n}\n'),
  },
  {
    ruleIds: [16], name: 'SEC-16 prop filled from a variable vs from a constant snippet',
    detects: f('src/app/chat.tsx', 'export const Chat = ({ html }: { html: string }) => <script id="c" dangerouslySetInnerHTML={{ __html: html }} />;\n'),
    ignores: f('src/app/chat.tsx', 'const QUEUE = "window.q = []";\nexport const Chat = () => <script id="c" dangerouslySetInnerHTML={{ __html: QUEUE }} />;\n'),
  },
  {
    ruleIds: [45], name: 'SEC-45 open read on user data vs on the plans catalog',
    detects: f('migrations/1_rls.sql', 'CREATE POLICY posts_read ON public.posts\n  FOR SELECT TO authenticated USING (true);\n'),
    ignores: f('migrations/1_rls.sql', 'CREATE POLICY plans_read ON public.plans\n  FOR SELECT TO authenticated USING (true);\n'),
  },
];

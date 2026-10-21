import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [37], name: 'SEC-37 SHA-1 on a token vs a torrent info hash, a migration name and a file checksum',
    detects: f('src/auth/reset.ts', "import crypto from 'crypto';\nexport function storeResetToken(token: string) {\n  return crypto.createHash('sha1').update(token).digest('hex');\n}\n"),
    ignores: [
      ...f('src/torrent/torrent.utils.ts', "import { createHash } from 'crypto';\nexport function infoHash(buffer: Buffer, start: number, end: number) {\n  return createHash('sha1').update(buffer.subarray(start, end)).digest('hex');\n}\n"),
      ...f('packages/cli/src/utils.ts', "import { createHash } from 'crypto';\nexport const fileChecksum = (data: Buffer) => createHash('md5').update(data).digest('hex');\n"),
    ],
  },
  {
    ruleIds: [29003], name: 'PYF-03 mark_safe with a raw value vs every value escaped',
    detects: f('app/views/notices.py', 'from django.utils.safestring import mark_safe\nfrom django.utils.html import escape\n\ndef notice(msg, obj):\n    return mark_safe(f\'{msg} <a href="{obj.url}">{escape(obj)}</a>\')\n'),
    ignores: f('app/tables/columns.py', 'from django.utils.safestring import mark_safe\nfrom django.utils.html import escape\n\ndef link(value):\n    return mark_safe(f\'<a href="{escape(value)}">{escape(value)}</a>\')\n\ndef attr(ns):\n    return mark_safe(\' data-namespace="%s"\' % escape(ns))\n'),
  },
  {
    ruleIds: [28838], name: 'GAP-38 PATCH route with no auth vs include_router dependencies and FastAPI docs_src',
    detects: f('app/api/items.py', 'from fastapi import APIRouter\n\nrouter = APIRouter()\n\n@router.patch("/items/{item_id}")\nasync def update_item(item_id: str, item: Item):\n    return await repo.update(item_id, item)\n'),
    ignores: [
      ...f('app/api/admin.py', 'from fastapi import APIRouter, Depends, FastAPI\n\nrouter = APIRouter()\n\n@router.delete("/items/{item_id}")\nasync def delete_item(item_id: str):\n    return await repo.delete(item_id)\n\napp = FastAPI()\napp.include_router(router, dependencies=[Depends(require_admin)])\n'),
      ...f('docs_src/body_updates/tutorial001_py310.py', 'from fastapi import FastAPI\n\napp = FastAPI()\n\n@app.patch("/items/{item_id}")\nasync def update_item(item_id: str, item: Item):\n    return item\n'),
    ],
  },
  {
    ruleIds: [21], name: 'SEC-21 token printed in app code vs a generated parser and a one-off script',
    detects: f('src/api/session.ts', 'export function login(user: { token: string }) {\n  console.log("issued", user.token);\n}\n'),
    ignores: [
      ...f('ext/graphql_c_parser_ext/parser.c', 'static void next(int yychar) {\n  yytoken = YYTRANSLATE (yychar);\n  YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);\n  printf("%d", token);\n}\n'),
      ...f('server/scripts/tinybird_test_workspace.py', 'workspace_token = create_workspace()\nprint(workspace_token)\n'),
    ],
  },
];

import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [28838], name: 'GAP-38 PATCH with an alias that is not auth vs an Annotated auth alias in the same file',
    detects: f('app/routes/mock.py', 'from typing import Annotated\nfrom fastapi import APIRouter, Depends\n\nDb = Annotated[Session, Depends(get_db)]\nrouter = APIRouter()\n\n@router.patch("/sessions/{mock_id}")\ndef patch_mock(mock_id: str, s: Db = None):\n    return mock.patch(s, mock_id)\n'),
    ignores: f('app/routes/mock.py', 'from typing import Annotated\nfrom fastapi import APIRouter, Depends\n\nAuth = Annotated[None, Depends(require_auth)]\nrouter = APIRouter()\n\n@router.patch("/sessions/{mock_id}")\ndef patch_mock(mock_id: str, _: Auth = None):\n    return mock.patch(mock_id)\n'),
  },
  {
    ruleIds: [7006], name: 'CLOUD-06 literal token in ENV vs tokenizer settings and a file path',
    detects: f('Dockerfile', 'FROM python:3.12-slim\nENV SERVICE_TOKEN=abc123def456\n'),
    ignores: f('Dockerfile', 'FROM python:3.12-slim\nENV TIKTOKEN_CACHE_DIR=/opt/tiktoken\nENV TIKTOKEN_ENCODING=cl100k_base\nENV SECRETS_DIR=/run/secrets\n'),
  },
  {
    ruleIds: [8830], name: 'PY-SEC-30 value formatted into SQL vs every placeholder filled by an identifier quoter',
    detects: f('app/store.py', 'def read(conn, table, value):\n    return conn.execute("SELECT * FROM %s WHERE name = %s" % (\n        quote_ident(table),\n        value))\n'),
    ignores: f('app/store.py', 'def read(conn, table, cols):\n    return conn.execute("SELECT %s FROM %s" % (\n        ", ".join(quote_ident(c) for c in cols),\n        quote_ident(table)))\n'),
  },
  {
    ruleIds: [8841], name: 'PY-SEC-41 extractall without a filter vs a filter passed through keyword unpacking',
    detects: f('scripts/unpack.py', 'import tarfile\nwith tarfile.open(path) as tar:\n    tar.extractall(tmp)\n'),
    ignores: f('scripts/unpack.py', 'import tarfile\nwith tarfile.open(path) as tar:\n    tar.extractall(tmp, **({"filter": "data"} if hasattr(tarfile, "data_filter") else {}))\n'),
  },
];

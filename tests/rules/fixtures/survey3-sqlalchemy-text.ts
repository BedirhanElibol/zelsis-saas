import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [29911],
    name: 'SECG-12 SQLAlchemy text() fragment with request value vs UI text() helper, migrations, and UPPER_CASE constants',
    detects: f('app/users/repo.py', `from sqlalchemy import text

def filter_users(session, User, email: str):
    return session.query(User).filter(text(f"email = '{email}'")).all()
`),
    ignores: [
      ...f('app/backoffice/views.py', `def render_payout_summary(max_refundable_display: str, x: list):
    label = text(f"Maximum refundable amount: {max_refundable_display}")
    header = text(f"Payout Attempts ({len(x)})")
    return label, header
`),
      ...f('alembic/versions/20260901_drop_idx.py', `import sqlalchemy as sa
from alembic import op

def upgrade(idx_name: str):
    op.execute(sa.text(f"DROP INDEX CONCURRENTLY IF EXISTS {idx_name}"))
`),
      ...f('app/db/index_ops.py', `import sqlalchemy as sa

_NAME = "idx_users_email"

def drop_named_index(session):
    session.execute(sa.text(f"DROP INDEX CONCURRENTLY IF EXISTS {_NAME}"))
`)
    ]
  },
  {
    ruleIds: [8804],
    name: 'PY-SEC-04 SQLAlchemy/cursor f-string SQL vs scripts/, placeholder joins, and migrations',
    detects: [
      ...f('app/services/users.py', `from sqlalchemy import text

def find_by_email(session, email: str):
    return session.execute(text(f"SELECT * FROM users WHERE email = '{email}'")).fetchall()
`),
      ...f('app/db/queries.py', `def find_by_name(cursor, name: str):
    cursor.execute(f"SELECT * FROM t WHERE name = '{name}'")
    return cursor.fetchall()
`)
    ],
    ignores: [
      ...f('scripts/cleanup_users.py', `def purge(cursor, cutoff: str):
    cursor.execute(f"DELETE FROM sessions WHERE created_at < '{cutoff}'")
`),
      ...f('tools/scripts/export.py', `def export_tenant(cursor, tenant_id: str):
    cursor.execute(f"SELECT * FROM events WHERE tenant_id = '{tenant_id}'")
`),
      ...f('app/repositories/batch.py', `def load_by_ids(cursor, ids: list[int]):
    placeholders = ", ".join("?" * len(ids))
    cursor.execute(f"SELECT * FROM items WHERE id IN ({placeholders})", ids)
    return cursor.fetchall()
`)
    ]
  }
];

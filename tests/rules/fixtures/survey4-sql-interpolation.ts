import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [18104],
    name: 'ORM-RAW-01 Drizzle sql.raw / Prisma query raw with controlled schema enum, constants, and column names vs request value',
    detects: f('src/repo/user.ts', `import { sql } from 'drizzle-orm';
export async function findUser(db: any, req: any) {
  const email = req.query.email;
  return db.execute(sql.raw(\`SELECT * FROM users WHERE email = '\${email}'\`));
}
`),
    ignores: [
      ...f('packages/schema/src/pusher.ts', `import { sql } from 'drizzle-orm';
export function mapEnum(enumDef: any) {
  const enumValues = Object.values(enumDef.values);
  return sql.raw(\`enum(\${enumValues.map((v) => \`'\${v}'\`).join(', ')})\`);
}
`),
      ...f('server/src/db/cache.ts', `import { sql } from 'drizzle-orm';
const SWEEP_LONG_STATEMENT_TIMEOUT_MS = 60000;
export async function setTimeout(tx: any) {
  await tx.execute(sql.raw(\`SET LOCAL statement_timeout = \${SWEEP_LONG_STATEMENT_TIMEOUT_MS}\`));
}
`),
      ...f('src/db/escaped.ts', `import { sql } from 'drizzle-orm';
export function listen(topic: string) {
  return sql.raw(\`LISTEN \${escapeIdentifier(topic)}\`);
}
`),
    ],
  },
  {
    ruleIds: [6043],
    name: 'DB-PERF-43 Unprepared Dynamic SQL Query Injections vs escaped identifiers',
    detects: f('src/db/query.ts', `export async function runQuery(client: any, userId: string) {
  return client.query(\`SELECT * FROM users WHERE id = \${userId}\`);
}
`),
    ignores: f('src/db/listen.ts', `export async function subscribe(client: any, topic: string) {
  await client.query(\`LISTEN \${client.escapeIdentifier(topic)}\`);
}
`),
  },
  {
    ruleIds: [18031],
    name: 'RUBY-SEC-01 Ruby on Rails SQL Injection vs controlled user_id, topic_id, table_name and subquery',
    detects: f('app/models/account.rb', `class Account < ApplicationRecord
  def self.find_by_name(name)
    Account.where("name = '#{name}'")
  end
end
`),
    ignores: [
      ...f('app/models/topic_user.rb', `class TopicUser < ApplicationRecord
  def self.track(user_id, topic_id)
    joins("LEFT OUTER JOIN group_users gu ON gu.group_id = groups.id AND gu.user_id = #{user_id}")
      .joins("LEFT OUTER JOIN topic_allowed_groups tag ON tag.topic_id = #{topic_id}")
  end
end
`),
      ...f('app/models/event.rb', `class Event < ApplicationRecord
  scope :labelled, -> {
    subquery = unscoped.select("#{table_name}.id, #{table_name}.name").to_sql
    joins("INNER JOIN (#{subquery}) as labelled_events ON labelled_events.id = #{table_name}.id")
  }
end
`),
    ],
  },
  {
    ruleIds: [9002],
    name: 'GO-02 SQL Injection via fmt.Sprintf vs query builder clause assembly',
    detects: f('internal/db/user.go', `package db
import (
    "database/sql"
    "fmt"
    "net/http"
)
func QueryUser(db *sql.DB, r *http.Request) (*sql.Rows, error) {
    id := r.URL.Query().Get("id")
    return db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))
}
`),
    ignores: f('internal/builder/query_builder.go', `package builder
import "fmt"
type QueryBuilder struct {
    finalQuery string
}
func (qb *QueryBuilder) WithAggregation(aggClause string) *QueryBuilder {
    qb.finalQuery = fmt.Sprintf("SELECT best_match_group as filter_group_id, %s as value FROM best_matches GROUP BY best_match_group ORDER BY best_match_group", aggClause)
    return qb
}
`),
  },
  {
    ruleIds: [9605],
    name: 'RUST-05 SQL Injection via format! vs parameterized template with table and clause placeholders',
    detects: f('src/db/users.rs', `pub fn find_user(email: &str) -> String {
    format!("SELECT * FROM users WHERE email = '{}'", email)
}
`),
    ignores: f('src/db/query_builder.rs', `pub fn build_query(table: &str, window_function: &str) -> String {
    format!(
        "SELECT {columns} FROM {events_table} WHERE id = ? GROUP BY {window_function}(window_start) ORDER BY {order_by} LIMIT ?",
        columns = "id, name",
        events_table = table,
        window_function = window_function,
        order_by = "id ASC",
    )
}
`),
  },
];

CASES.push({
  ruleIds: [18104],
  name: 'ORM-RAW-01 a request value named v is still caught; only the quoted map item is safe',
  detects: f('src/repo/search.ts', `import { sql } from 'drizzle-orm';
export async function search(db: any, req: any) {
  const v = req.query.q;
  return db.execute(sql.raw(\`SELECT * FROM posts WHERE title = '\${v}'\`));
}
`),
  ignores: [],
});

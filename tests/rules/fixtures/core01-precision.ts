import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [24101], name: 'CORE-01 value spliced into SQL vs constants, numbers, generated SQL, PHP table names, prose and migrations',
    detects: f('app/cluster/init_cluster.py', `def save(cursor, cluster_id, config):
    cursor.execute(f"UPDATE am_cluster SET cluster_config = '{config}' WHERE cluster_id = '{cluster_id}'")
`),
    ignores: [
      ...f('app/memory/lessons.py', `_TABLE = "lessons"

def latest(conn):
    return conn.execute(f"SELECT MAX(ran_at) AS t FROM {_TABLE}").fetchone()
`),
      ...f('app/models/inbox.rb', `class Inbox
  def busy(limit, user)
    Conversation.group(:assignee_id).having("count(*) >= #{limit.to_i}").where("user_id = #{user.id}")
  end

  def nested(scope)
    Post.where("EXISTS (#{scope.select(1).to_sql})")
  end
end
`),
      ...f('src/Console/Importer.php', `<?php
class Importer {
  public function count($table) {
    return $this->pdo->query('SELECT COUNT(*) FROM ' . $table)->fetchColumn();
  }
}
`),
      ...f('src/sentry/requester.py', `def fail(slug):
    raise ValueError(f"Something went wrong while getting options for Select FormField from {slug}")
`),
      ...f('app/db/alembic/versions/20260724_add_rollups.py', `def upgrade():
    op.execute(f"DELETE FROM rollups WHERE bucket = '{bucket}'")
`),
    ],
  },
];

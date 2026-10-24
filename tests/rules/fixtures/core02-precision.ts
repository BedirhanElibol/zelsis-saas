import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [24102], name: 'CORE-02 shell command from a value vs DB exec, doc backticks, escaped args, argv lists and PHP method names',
    detects: [
      ...f('app/services/thumbs.rb', 'class Thumbs\n  def size(path)\n    `identify -format "%wx%h " #{path}`.split(/x/)\n  end\nend\n'),
      ...f('app/tools/ping.py', 'import os\n\ndef ping(host):\n    os.system("ping -c 1 " + host)\n'),
    ],
    ignores: [
      ...f('app/db/preflight.rb', 'class Preflight\n  def setting(connection, name)\n    connection.exec("SHOW #{name};").first[name]\n  end\n\n  def timeout(ms)\n    DB.exec "SET LOCAL statement_timeout = #{ms}"\n  end\nend\n'),
      ...f('activerecord/lib/active_record/reflection.rb', 'module Reflection\n  def message(foreign_key)\n    raise ArgumentError, <<~MSG\n      The query constraints\n      `#{primary_query_constraints}` and the foreign key is `#{foreign_key}`.\n    MSG\n  end\n\n  def error(ref)\n    raise ArgumentError, "Could not resolve the file (`#{ref}`)."\n  end\nend\n'),
      ...f('app/models/account/import.rb', 'class Import\n  def free_space(path)\n    `df -Pk #{Shellwords.escape(path)} 2>/dev/null`.lines.last\n  end\n\n  def rss(daemon)\n    `ps -o rss= -p #{daemon.pid}`.chomp.to_i\n  end\nend\n'),
      ...f('app/net/ports.py', 'import subprocess\n\ndef pid_on(port):\n    return subprocess.check_output(["lsof", "-ti", f"TCP:{port}"], text=True)\n'),
      ...f('app/workers/main.py', 'import os\n\ndef start():\n    os.system("celery multi start w1 -A app.celery worker --pidfile=/var/run/celery/%n.pid")\n'),
      ...f('packages/http/src/View.php', '<?php\nclass View {\n  public function exec($view): string {\n    return $this->render($view);\n  }\n}\n'),
    ],
  },
];

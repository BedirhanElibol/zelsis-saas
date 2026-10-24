import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [8802],
    name: 'Rule 8802 PyYAML load without SafeLoader vs pattern lists, regex strings, and safe loaders',
    detects: f('app/loader.py', `import yaml

def load_config(raw_yaml):
    cfg = yaml.load(raw_yaml)
    return cfg
`),
    ignores: f('tools/linter_rules.py', `import yaml

PY_PATTERNS = [
    ("Python yaml.load() without Loader=Safe", r"yaml\\.load\\("),
]

REMEDIATION_GUIDE = "Use yaml.safe_load() or pass Loader=SafeLoader to yaml.load()."

CHECK_DICT = {
    "yaml_check": "flags yaml.load() when called directly"
}

def load_safely(raw_yaml):
    return yaml.load(raw_yaml, Loader=yaml.SafeLoader)
`),
  },
  {
    ruleIds: [29105],
    name: 'Rule 29105 Rails constantize on params vs code comments illustrating vulnerable patterns',
    detects: f('app/controllers/exports_controller.rb', `class ExportsController < ApplicationController
  def create
    exporter = params[:type].constantize.new(current_user)
    send_data exporter.call
  end
end
`),
    ignores: f('lib/brakeman/check_sql.rb', `class CheckSql
  # Example vulnerable pattern:
  # params[:x].constantize.find('something')
  # Do not flag comments like above!
  def run_check
    # params[:class].safe_constantize
    nil
  end
end
`),
  },
];

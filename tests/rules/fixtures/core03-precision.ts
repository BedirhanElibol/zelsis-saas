import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [24103], name: 'CORE-03 pickle of a request body vs deep copies, Psych 4 YAML.load, FullLoader, allow-listed unserialize and homework',
    detects: f('app/views.py', 'import pickle\nfrom flask import request\n\ndef restore():\n    return pickle.loads(request.get_data())\n'),
    ignores: [
      ...f('lib/selector/base.rb', 'class Base\n  def initialize(selector)\n    @selector = Marshal.load(Marshal.dump(selector)).deep_symbolize_keys\n  end\nend\n'),
      ...f('lib/credentials.rb', 'class Credentials\n  def parse(yaml)\n    YAML.load(yaml)\n  end\nend\n'),
      ...f('app/swagger.py', 'import yaml\n\ndef tags(path):\n    with open(path) as f:\n        return yaml.load(f.read(), Loader=yaml.FullLoader)\n'),
      ...f('src/Routing/RouteSignatureParameters.php', "<?php\nclass RouteSignatureParameters {\n  public static function fromAction($action) {\n    return unserialize($action['uses'], ['allowed_classes' => [SerializableClosure::class]]);\n  }\n}\n"),
      ...f('cohorts/2023/05-deployment/homework/q6_predict.py', 'import pickle\n\nwith open("model.bin", "rb") as f_in:\n    model = pickle.load(f_in)\n'),
    ],
  },
];

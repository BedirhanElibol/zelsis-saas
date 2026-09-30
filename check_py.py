import os
import re

catalogs_dir = r"C:\Users\Bedirhan\.gemini\antigravity\worktrees\newday\evaluate_app_deployment_readiness\data\catalogs"
files = [os.path.join(catalogs_dir, f) for f in os.listdir(catalogs_dir) if f.endswith('.ts')]

missing_c1 = []
wrong_ast = []

for f in files:
    with open(f, 'r', encoding='utf-8') as file:
        content = file.read()
        
        # Split rules by "{ id:" or "{ \n  id:"
        # Since it's typescript, we can just split by "  {" assuming standard formatting
        # Better: use regex to find blocks starting with { and having an id: property
        
        rules = re.findall(r'{\s*id:\s*.*?(?=,\s*id:|\n  },|\n  }\n\])', content, re.DOTALL)
        
        # let's be simpler: count total "id:" in file vs total "sourceUrl:"
        
        id_count = len(re.findall(r'\bid:\s*(?:\d+|[\'"].*?[\'"])', content))
        sourceUrl_count = len(re.findall(r'sourceUrl:', content))
        
        if id_count > sourceUrl_count:
            missing_c1.append(f)
            
        # Check AST
        # Let's find every detectionMethod and see if it uses AST but description/title says AST
        rule_blocks = re.split(r'{\s*id:\s*(?:\d+|[\'"].*?[\'"])', content)[1:]
        for block in rule_blocks:
            is_ast = 'detectionMethod: "ast"' in block or "detectionMethod: 'ast'" in block
            is_regex_or_lexical = 'regex' in block or 'lexical' in block
            if not is_ast and ('AST ' in block or ' AST ' in block):
                if is_regex_or_lexical:
                    wrong_ast.append(f)

print("C1 missing files:", len(missing_c1), missing_c1[:2])
print("C3 wrong AST rules:", len(wrong_ast), wrong_ast[:2])

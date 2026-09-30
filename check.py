import os
import re

catalogs_dir = r"C:\Users\Bedirhan\.gemini\antigravity\worktrees\newday\evaluate_app_deployment_readiness\data\catalogs"
files = [os.path.join(catalogs_dir, f) for f in os.listdir(catalogs_dir) if f.endswith('.ts')]

c1_missing = []
c2_old_owasp = []
c3_ast_wrong = []
c4_descriptions = []

for f in files:
    with open(f, 'r', encoding='utf-8') as file:
        content = file.read()
        
        # Split by something like rule objects, or just basic checks
        # 1. Check if source_url, source_type, positive_example, negative_example exist in the file globally?
        # Actually it's better to check individual rules.
        
        # 2. Are all OWASP references updated to "OWASP 2025"?
        # Find any "OWASP" that is NOT followed by " 2025"
        old_owasp = re.findall(r'OWASP(?! 2025)', content)
        if old_owasp:
            c2_old_owasp.append((f, old_owasp))
        
        # 3. Is the word "AST" only used for true AST rules (and not regex/lexical rules)?
        # 4. Are there any template-duplicated descriptions?
        
print("C2 Old OWASP:", c2_old_owasp)

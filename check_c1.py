import os
import re

catalogs_dir = r"C:\Users\Bedirhan\.gemini\antigravity\worktrees\newday\evaluate_app_deployment_readiness\data\catalogs"
files = [os.path.join(catalogs_dir, f) for f in os.listdir(catalogs_dir) if f.endswith('.ts')]

missing_c1 = []
missing_details = []

for f in files:
    with open(f, 'r', encoding='utf-8') as file:
        content = file.read()
        
        id_count = len(re.findall(r'\bid:\s*(?:\d+|[\'"].*?[\'"])', content))
        s_url = len(re.findall(r'sourceUrl:', content))
        s_type = len(re.findall(r'sourceType:', content))
        p_ex = len(re.findall(r'positiveExample:', content))
        n_ex = len(re.findall(r'negativeExample:', content))
        
        if not (id_count == s_url == s_type == p_ex == n_ex):
            missing_c1.append(f)
            missing_details.append(f"{os.path.basename(f)}: ids={id_count}, url={s_url}, type={s_type}, p={p_ex}, n={n_ex}")

print("C1 missing files:", len(missing_c1))
for d in missing_details:
    print(d)

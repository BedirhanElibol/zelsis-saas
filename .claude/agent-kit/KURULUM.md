# .agentsforclaude

`newday/.agent` (Antigravity Kit) içeriğinin Claude Code'a uyarlanmış hali.
Bu klasör doğrudan bir `.claude/` klasörü gibi düzenlendi.

## İçerik

| Klasör | Ne | Claude Code karşılığı |
|---|---|---|
| `agents/` | 19 ajan | Subagent — "backend-specialist ile ..." diye iste |
| `skills/` | 344 skill | Otomatik seçilir ya da `/skill-adı` ile çağrılır |
| `commands/` | 11 workflow | `/ag-create`, `/ag-debug`, `/ag-plan`, `/ag-test`, `/ag-deploy`, `/ag-orchestrate`, `/ag-brainstorm`, `/ag-enhance`, `/ag-preview`, `/ag-status`, `/ag-ui-ux-pro-max` |
| `agent-kit/rules/KIT_RULES.md` | Eski `GEMINI.md` | Otomatik yüklenmez (aşağıya bak) |
| `agent-kit/scripts/` | checklist, verify_all, auto_preview, session_manager, watch_push | `python .claude/agent-kit/scripts/checklist.py .` |
| `agent-kit/shared/` | ui-ux-pro-max veri + arama script'i | `/ag-ui-ux-pro-max` kullanır |
| `agent-kit/docs/`, `tasks/`, `tooling/` | Orijinal dokümanlar, görevler, katalog araçları | Referans |

## Yapılan dönüşümler

- `.agent/...` yolları `.claude/...` yapısına çevrildi (skills, agents, commands, agent-kit).
- Workflow komutlarına `ag-` öneki eklendi; `/status`, `/plan` gibi yerleşik komutlarla çakışmasın diye.
- `@[skills/x]` referansları `.claude/skills/x/SKILL.md` yoluna çevrildi.
- Antigravity'ye özel `ViewCodeItem`, `FindByName` araçları ajanlardan çıkarıldı (Grep/Glob zaten var).

## newday'de nasıl kurulu

Kit, zelsis-saas repo'suna commit edildi (`chore/claude-agent-kit` branch'i). Böylece masaüstü uygulamasının
açtığı her worktree oturumu `.claude/agents`, `skills`, `commands`, `agent-kit` ve `CLAUDE.md` §7'yi alır.

Repo public olduğu için şunlar commit edilmedi, `.gitignore` ile yerelde tutuluyor (tam halleri bu klasörde):
`agent-kit/tasks/` (Carvis görevleri), `agent-kit/docs/ProjeSonra.md`, `Proje_Gelistirme_Rehberi.md`,
`extracted_*.txt`, `*.png`.

ESLint `.claude/**` klasörünü yok sayacak şekilde ayarlandı (kit içindeki .js dosyaları lint'e girmesin).

## Başka bir projeye kurmak

Bu klasörün içindekileri projenin `.claude/` klasörüne kopyala:

```
agents/  skills/  commands/  agent-kit/  ->  <proje>/.claude/
```

Masaüstü uygulaması oturumları worktree'de açtığı için en sağlamı bunları repo'ya commit etmek.
Commit edilmezse ajan/skill/komutlar yine yüklenir ama `CLAUDE.md` importu ve `agent-kit/` script'leri
worktree'de bulunmaz. Repo public ise yukarıdaki kişisel dosyaları `.gitignore`'a ekle.

## KIT_RULES.md'yi açmak

Orijinal GEMINI.md her istekte zorunlu kurallar uygular (her işten önce 3 soru sorma, "🤖 Applying knowledge..."
çıktısı, mor renk yasağı vb.). Kendiliğinden yüklenmez; projenin `CLAUDE.md` dosyasına şunu ekle:

```
# 7. Agent Kit Rules
- Precedence: KIT_RULES.md overrides sections 1-6 on any conflict (except section 4 Hard Constraints).
@.claude/agent-kit/rules/KIT_RULES.md
```

KIT_RULES çakışmalarda `CLAUDE.md`'yi ezer; yalnızca "Hard Constraints" listesi her zaman geçerli kalır.
İçindeki "PROJECT RULES: Zelsis" bölümü newday'in `CLAUDE.md`'sinden alındı (stack, konvansiyonlar,
hard constraints, git, doğrulama komutları). Başka bir projede kullanırken bu bölümü o projeye göre değiştir.

## Uyarı

`agent-kit/scripts/watch_push.js` dosya değişikliklerini izleyip otomatik `git push` yapar. Hiçbir yerde
otomatik çalıştırılmıyor; çalıştırmadan önce iyi düşün.

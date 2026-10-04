# 🤖 Carvis-App .agent Kapsamlı Rehberi (Antigravity Kit)

Bu rehber, `.agent` klasörü içindeki tüm dosyaların, uzmanların (agents), yeteneklerin (skills) ve iş akışlarının (workflows) eksiksiz listesini ve kullanım amaçlarını içerir.

---

## 1. 📜 Rules (Kurallar) - `.claude/agent-kit/rules/`
*   **KIT_RULES.md**: Uygulamanın temel anayasası. Türkçe iletişim, Clean Code prensipleri ve Socratic Gate protokolü burada tanımlıdır.

---

## 2. 🧠 Agents (Uzmanlar) - `.claude/agents/`
Her dosya, belirli bir konuda derin uzmanlığa sahip bir yapay zeka personasını temsil eder.

| Uzman Dosyası | Görevi / Uzmanlık Alanı |
| :--- | :--- |
| **backend-specialist.md** | API, veritabanı (Supabase) ve sunucu taraflı mantık. |
| **code-archaeologist.md** | Mevcut karmaşık kod tabanını analiz eder ve geçmiş kararları anlar. |
| **database-architect.md** | Veritabanı şeması tasarımı, sorgu optimizasyonu ve veri güvenliği. |
| **debugger.md** | Karmaşık hataların kök nedenini bulma ve kalıcı çözüm üretme. |
| **devops-engineer.md** | CI/CD süreçleri, sunucu yapılandırması ve deployment (yayına alma). |
| **documentation-writer.md** | Teknik dokümantasyon, README ve API dökümanlarını yazar. |
| **explorer-agent.md** | Proje yapısını keşfeder, dosya ilişkilerini analiz eder. |
| **frontend-specialist.md** | React, Tailwind, UI/UX tasarımı ve premium kullanıcı deneyimi. |
| **game-developer.md** | Oyun mekanikleri (eğer projede varsa) ve etkileşimli öğeler. |
| **mobile-developer.md** | React Native/Expo ile mobil uygulama geliştirme süreçleri. |
| **orchestrator.md** | Diğer tüm uzmanları koordine eden ana yönetim birimi. |
| **penetration-tester.md** | Güvenlik testleri yapar, sisteme "beyaz şapkalı hacker" gözüyle bakar. |
| **performance-optimizer.md** | Hız, bundle boyutu ve kaynak kullanımı optimizasyonu. |
| **product-manager.md** | Kullanıcı ihtiyaçlarını analiz eder, özellik önceliklendirmesi yapar. |
| **project-planner.md** | Görevleri parçalara böler, süre ve dependency (bağımlılık) planlar. |
| **qa-automation-engineer.md** | Otomatik test senaryoları tasarlar ve kalite kontrol yapar. |
| **security-auditor.md** | Kod güvenliği, şifreleme ve yetkilendirme denetimi. |
| **seo-specialist.md** | Arama motoru optimizasyonu ve sayfa performansı (Core Web Vitals). |
| **test-engineer.md** | Birim (Unit) ve entegrasyon testlerinin mimarisini kurar. |

---

## 🛠️ 3. Skills (Yetenekler) - `.claude/skills/`
Asistanın profesyonel çıktılar üretmek için başvurduğu teknik bilgi kütüphaneleridir.

| Yetenek Klasörü | Amacı ve İçeriği |
| :--- | :--- |
| **api-patterns** | REST/GraphQL standartları ve veri alışverişi prensipleri. |
| **app-builder** | Uygulama iskeletini kurma ve modüler yapı oluşturma. |
| **architecture** | Sistem mimarisi kararları ve dokümantasyonu. |
| **bash-linux** | Linux terminal komutları ve otomasyon betikleri. |
| **behavioral-modes** | Farklı çalışma modları (Düşün, Planla, Uygula) yönergeleri. |
| **brainstorming** | Fikir geliştirme ve seçenek analizi protokolleri. |
| **clean-code** | SOLID, DRY ve okunabilir kod standartları. |
| **code-review-checklist**| Kod denetimi sırasında bakılacak kritik noktalar. |
| **database-design** | İlişkisel veritabanı tasarımı ve normalizasyon kuralları. |
| **deployment-procedures**| Güvenli yayına alma ve geri alma (rollback) stratejileri. |
| **documentation-templates**| Standart dökümantasyon formatları. |
| **frontend-design** | Modern tasarım ilkeleri, animasyon ve estetik kuralları. |
| **game-development** | Oyun geliştirme prensipleri ve motor bilgisi. |
| **geo-fundamentals** | Yapay zeka arama motorları (GEO) için optimizasyon. |
| **i18n-localization** | Çoklu dil desteği ve yerelleştirme (Localization) yönetimi. |
| **intelligent-routing** | Gelen talebi doğru uzmana yönlendirme zekası. |
| **lint-and-validate** | Kod yazım standartlarının (ESLint vb.) kontrolü. |
| **mcp-builder** | Model Context Protocol (MCP) sunucusu geliştirme rehberi. |
| **mobile-design** | Mobil cihazlara özel UX ve etkileşim kuralları. |
| **nextjs-best-practices**| Next.js App Router ve Server Components standartları. |
| **nodejs-best-practices**| Node.js performansı ve güvenli çalışma yöntemleri. |
| **parallel-agents** | Birden fazla uzmanın aynı anda çalışması protokolü. |
| **performance-profiling** | Darboğaz (bottleneck) tespiti ve performans ölçümü. |
| **plan-writing** | Teknik iş planı yazma standartları. |
| **powershell-windows** | Windows ortamında komut ve otomasyon yönetimi. |
| **python-patterns** | Python tabanlı betikler için en iyi uygulamalar. |
| **react-patterns** | Custom Hooks, bileşen kompozisyonu ve State yönetimi. |
| **red-team-tactics** | Ofansif güvenlik denetimi ve açık tarama. |
| **seo-fundamentals** | SEO temelleri ve Google algoritma uyumluluğu. |
| **server-management** | Sunucu sağlığı ve kaynak yönetimi. |
| **systematic-debugging** | Kanıta dayalı ve adım adım hata ayıklama süreci. |
| **tailwind-patterns** | Tailwind v4 ve modern CSS yapılandırma kuralları. |
| **tdd-workflow** | Test-Driven Development (Önce Test) iş akışı. |
| **testing-patterns** | AAA (Arrange-Act-Assert) gibi test yazım standartları. |
| **vulnerability-scanner** | Zafiyet taraması ve güvenlik risk analizi. |
| **webapp-testing** | Web uygulamaları için derinlemesine test stratejileri. |

---

## 🔄 4. Workflows (İş Akışları) - `.claude/commands/`
Sık kullanılan kompleks işlemler için tanımlanmış komutlar.

| Komut / Dosya | Ne Zaman Kullanmalısın? |
| :--- | :--- |
| **`/ag-brainstorm`** | Bir konu hakkında henüz net bir fikrin yoksa, seçenekleri tartışmak için. |
| **`/ag-create`** | Yepyeni bir proje veya büyük bir modül başlatırken. |
| **`/ag-debug`** | Çözülemeyen inatçı teknik sorunları analiz etmek ve düzeltmek için. |
| **`/ag-deploy`** | Kodun production (canlı) ortamına gitmeye hazır olduğunu doğrulamak için. |
| **`/ag-enhance`** | Mevcut bir özelliğe ekstra yetenekler eklemek isterken. |
| **`/ag-orchestrate`** | Çok büyük işleri birden fazla uzmanın koordinasyonuyla yapmak için. |
| **`/ag-plan`** | Her türlü geliştirme öncesi riskleri ve adımları belirlemek için. |
| **`/ag-preview`** | Yerel sunucuyu açıp yaptığımız değişikliklere bakmak için. |
| **`/ag-status`** | Projede kim neyi bitirdi, şu an ne üzerinde çalışıyoruz görmek için. |
| **`/ag-test`** | Kodun doğruluğunu onaylamak ve hata kontrolü yapmak için. |
| **`/ag-ui-ux-pro-max`** | Uygulamayı görsel olarak en üst seviyeye taşımak istediğinde. |

---

## 🚀 Önemli Tavsiye:
Bir şeye başlamadan önce **`/ag-plan`** komutunu kullanmak her zaman en iyisidir. Bu sayede ben yukarıdaki tüm **Uzmanlarımı** ve **Yeteneklerimi** kullanarak sana en güvenli ve en kaliteli yolu çizerim.

# Zelsis SaaS - Yüksek Değerli & Ödemeye Değer SaaS/App Kuralları Araştırma ve Entegrasyon Planı

## 1. Giriş ve Amaç
Zelsis'in GitHub repo tarayıcısı, canlı sitelerin aksine projenin tüm kaynak koduna (backend API rotaları, veritabanı şemaları ve migration'lar, ödeme entegrasyonları, LLM/AI çağrıları, arka plan kuyrukları ve auth mekanizmaları) tam erişime sahiptir.

Kullanıcıların Zelsis'e severek ödeme yapması ve "İyi ki Zelsis kullanıyorum, beni felaketten kurtardı" demesi için; teorik/akademik kurallar yerine **SaaS kurucularının ve yazılım ekiplerinin canını yakan, para kaybettiren, veritabanlarını kilitleyen veya müşteri verilerini sızdıran gerçek dünya risklerine** odaklanacağız.

---

## 2. Araştırma ve Odak Alanları (High-Value Rule Domains)

### Alan 1: Gelir ve Fatura Kaçakları (Revenue & Payment Protection)
- **Stripe / Polar / LemonSqueezy Webhook Race Conditions:** Ödeme henüz onaylanmadan veya iptal edildikten sonra lisansın açık kalması, idempotency eksikliği nedeniyle çift iade/çift kredi yükleme.
- **İstemci Taraflı Fiyat/Plan Manipülasyonu:** Checkout oturumu oluştururken fiyat veya ürün ID'sinin client-side parametreden doğrudan backend'e güvenilerek gönderilmesi.
- **Eksik Yetki İptali (Revocation Lag):** Aboneliğini iptal eden kullanıcının JWT süresi dolana kadar (7-30 gün) korumalı kaynaklara erişmeye devam etmesi.

### Alan 2: "Denial-of-Wallet" & AI Maliyet Patlamaları (Cloud Cost Defense)
- **Bağlantı Koptuğunda Devam Eden LLM Çağrıları:** İstemci sekmesini kapattığında Next.js / Node.js sunucusunun OpenAI/Anthropic/Claude API streaming çağrısını `AbortController` (`req.signal`) ile iptal etmemesi ve fatura yazmaya devam etmesi.
- **Sınırsız Token Tüketim Döngüleri:** Kullanıcı girdilerine `max_tokens` veya karakter/token sınırlandırılması konulmaması, prompt injection ile 128k context'lik maliyet saldırılarına açık bırakılması.
- **Harcama Öncesi Bakiye/Kota Kontrolü Eksikliği:** AI çağrısı yapılmadan önce kullanıcının veritabanındaki kredi bakiyesinin atomik olarak rezerve edilmemesi (race condition ile eksiye düşme).

### Alan 3: Çok Kiracılı (Multi-Tenant) Veri Sızıntıları (Tenant Isolation & Trust)
- **Cross-Tenant IDOR Açıkları:** Prisma, Drizzle veya SQL sorgularında yalnızca `WHERE id = $1` kullanılıp `tenant_id` veya `org_id` koşulunun unutulması.
- **Log ve Telemetriye Sızan Hassas Veriler:** Sentry, PostHog, Axiom veya Datadog loglarına `Authorization` token'ları, API key'leri, Stripe müşteri bilgileri veya kullanıcı PII verilerinin maskelenmeden gitmesi.

### Alan 4: Dağıtım Anında Veritabanı ve Servis Kilitlenmeleri (Zero-Downtime Reliability)
- **Tehlikeli PostgreSQL Migration'ları:** Canlı tablolara `DEFAULT` değeri olmadan `NOT NULL` kolon ekleme, unindexed foreign key'ler, eşzamanlı indeks oluşturma (`CONCURRENTLY`) yerine tabloyu kitleyen indeksler.
- **Serverless Soğuk Başlangıç & DB Bağlantı Patlaması (Connection Pool Exhaustion):** Serverless fonksiyonlarda global pooling yapılmaması nedeniyle Supabase / RDS bağlantı limitinin 10 saniyede tükenmesi.

---

## 3. /orchestrate Faz Planı

### Faz 1: Planlama ve Kullanıcı Onayı (Mevcut Aşama)
- Kullanıcı ile odak noktaları ve hedef kuralların etki alanları üzerinde mutabakat sağlanması (Socratic Gate).

### Faz 2: Çoklu Ajan ile Canlı Piyasa & Topluluk Taraması (`/browser` & Özel Ajanlar)
- **`browser` Ajanı:** Hacker News, Reddit (r/SaaS, r/webdev), GitHub Security Lab, PostHog/Stripe blogları ve modern SaaS post-mortem raporlarını tarayarak en sık yaşanan felaketleri ve maliyet açıklarını listeler.
- **`security-auditor` Ajanı:** Taranan bulguları analiz ederek Zelsis için uygulanabilir kural spesifikasyonlarına (CVE, CWE, OWASP 2025, regex/AST deseni, pozitif/negatif kod örnekleri) dönüştürür.
- **`backend-specialist` Ajanı:** Next.js 15, Node.js, Supabase, Prisma, Drizzle, Stripe ve AI SDK entegrasyonlarına özel somut otomatik düzeltme (auto-fix / Cursor prompt) şablonlarını tasarlar.

### Faz 3: Zelsis Motoruna Entegrasyon ve Doğrulama
- Seçilen kuralların `lib/rules/` dizinine eklenmesi.
- Her yeni kural için gerçek dünya test senaryolarının (`tests/`) yazılması.
- `npm run build` ve lint doğrulamalarının yapılması.

---

## 4. Başarı Kriterleri
1. Taranan her yeni kuralın arkasında **somut bir maddi kayıp veya güvenlik felaketi senaryosu** olması.
2. Sıfır false-positive (yanlış alarm) garantisi; derlenmiş kod ile kaynak kodun net ayrılması.
3. Kullanıcıya bulunan açığın tam olarak **neden para/veri kaybettireceğini** açıklayan ve **1 tıkla düzeltme sağlayan** açıklayıcı geri bildirim sunması.

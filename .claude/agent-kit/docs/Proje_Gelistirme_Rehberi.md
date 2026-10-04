# 🚀 YAZILIM, TASARIM VE GÜVENLİK MASTER KONTROL LİSTESİ

Bu kapsamlı rehber; web tabanlı SaaS platformları, mobil uygulamalar ve yapay zeka odaklı iş akışlarında yüksek kalite standartlarını sağlamak için oluşturulmuştur. Tailwind CSS, Supabase, Vercel gibi modern mimarilerde çalışırken; Cursor veya DeepSeek gibi model destekli otopilot ajanların üretebileceği jenerik tasarımları, performans darboğazlarını ve güvenlik açıklarını engellemek adına ana bir referans noktasıdır.

---

## 🤖 1. AI SLOP VE PROBLEM KATALOĞU
*Yapay zeka (LLM) uygulamalarında sıklıkla yapılan hatalar ve profesyonel çözümleri.*

### Bölüm 1: UI/UX & Tasarım "AI Slop" Göstergeleri
1. **Jenerik Mor-Mavi Gradyanlar:** Her butonda anlamsız neon/mor gradyan kullanımı. -> *Çözüm: Gradyan yerine anlamsal düz renk paleti tanımlayın; marka kimliğini tipografi ve negatif alanla verin.*
2. **"Inter" Font Monotonluğu:** Karakteri olmayan varsayılan sistem yazı tipleri. -> *Çözüm: Başlıklar için amaca uygun bir display yazı tipi, gövde için okunaklı sans/serif kombinasyonu seçin.*
3. **Sihirli Değnek / Sparkle İkon İstilası:** Her aksiyon alanına parıltı ikonu basılması. -> *Çözüm: İkonu kaldırın; eylemi anlatan net metinler ("Özetle", "Filtrele") kullanın.*
4. **Boş Durum (Empty State) Yokluğu:** İlk girişte boş ekranın rehberlik etmemesi. -> *Çözüm: Sıfır veri anında tek tıkla çalıştırılabilir şablonlar sunun.*
5. **Eksik Hata & Yükleme Durumları:** Model çöktüğünde donan UI. -> *Çözüm: Optimistic UI, skeleton loaders ve yeniden deneme butonlu hata bildirimleri ekleyin.*
6. **Aşırı Düzgün 16px Radius / 24px Padding Simetrisi:** Tüm bileşenlerin aynı kalıpla üretilmiş hissi vermesi. -> *Çözüm: Hiyerarşik boşluklandırma ve değişken konteyner boyutları uygulayın.*
7. **Sadece Chat Arayüzüne Mahkum Etmek:** Form veya tablo gerektiren işi sadece bir mesajlaşma kutusuna sıkıştırmak. -> *Çözüm: Hibrit arayüzler (Artifacts/Canvas) inşa edin.*
8. **Statik Markdown Çıktıları:** Çıktının ham text olarak bırakılması, düzenlenememesi. -> *Çözüm: Çıktıyı doğrudan kopyalanabilir ve inline düzenlenebilir bloklara ayırın.*
9. **Tek Düze Geçiş Animasyonları:** Bütün elemanların aynı 300ms fade-in ile gelmesi. -> *Çözüm: Durum değişimine odaklanan fizik tabanlı mikro etkileşimler kullanın.*
10. **Bilişsel Yük:** Tüm panellerin tek ekranda yığılması. -> *Çözüm: Aşamalı açıklama (progressive disclosure) kullanın.*
11. **Gereksiz "AI Düşünüyor..." Spinner'ları:** Belirsiz ekranlar. -> *Çözüm: Ajanın adımlarını şeffaf bir stepper bileşeniyle gösterin.*
12. **Geri Al (Undo) Eksikliği:** Eski sürüme dönülememesi. -> *Çözüm: Diff görüntüleyici ve tek tıkla geri alma mekanizması kurun.*
13. **Seçim Yapılamayan Toplu Yeniden Üretim:** Beğenilmeyen küçük bir kısım için tüm çıktının sıfırdan üretilmesi. -> *Çözüm: Parça seçim ve inline yeniden üretim özelliği ekleyin.*
14. **Görsel Hiyerarşi Bozukluğu:** Başlık ve gövde metinlerinin kontrast farkının yetersizliği. -> *Çözüm: Sıkı kontrast oranları ve net tipografik boyut skalası uygulayın.*
15. **Hareketsiz Streaming Titremesi:** Metin stream edilirken sayfanın zıplaması. -> *Çözüm: scroll-anchor sabitlemesi ve tahmini yükseklik tutucular kullanın.*
16. **Mobil Uyumsuz Geniş Tablolar:** AI çıktısındaki geniş tabloların mobil ekranda taşması. -> *Çözüm: Mobilde tabloyu dikey kart görünümlerine dönüştüren responsive renderer yazın.*
17. **Aşırı Aydınlık/Karanlık Kontrastsız Temalar:** Kontrastsız grimsi koyu veya göz yoran açık mod. -> *Çözüm: Algısal olarak dengeli gri tonları (slate/zinc) kullanın.*
18. **Gereksiz Modal Pencereler:** Tüm ekranı kilitleyen modallar. -> *Çözüm: Popover veya slide-over çekmeceler (drawer) tercih edin.*
19. **Klavye Kısayolları Yokluğu:** Fareye bağımlı AI tetikleme. -> *Çözüm: Cmd+K / Ctrl+K komut paleti ekleyin.*
20. **Meta-Geri Bildirim Eksikliği:** Kullanıcının çıktıyı neden aldığını anlayamaması. -> *Çözüm: Çıktının altına kaynak rozeti ekleyin.*

### Bölüm 2: Metin, Üslup & Çıktı Kalitesi Semptomları
1. **Klişe Dolgu Cümleleri (Fluff):** "In today's fast-paced digital world..." ile başlama. -> *Çözüm: System prompt'a dolgu kalıplarını yasaklayan kural seti ekleyin.*
2. **Dalkavukluk (Sycophancy):** Kullanıcının hatalı önermesini onaylama. -> *Çözüm: Bağımsız doğrulama kuralı koyun.*
3. **Robotik Özürler:** "As an AI language model..." gibi klişe retler. -> *Çözüm: Doğal sistem mesajları tanımlayın, direkt çözüme yönlendirin.*
4. **Aşırı Uzun Yanıtlar:** 2 satırlık cevabı 5 paragrafa yaymak. -> *Çözüm: Çıktı formatına sert kelime limiti getirin.*
5. **Etiketli Kapanışlar:** Yapay özet paragrafları eklemek. -> *Çözüm: Kapanış etiketlerini yasaklayın.*
6. **Monoton Ton & Duygu Eksikliği:** Ruhsuz ve ansiklopedik çıktı. -> *Çözüm: Hedef kitleye özel Persona ve Tone profilleri tanımlayın.*
7. **"Not Only, But Also" Döngüsü:** Sürekli ikili karşılaştırma cümleleri. -> *Çözüm: Few-shot örnekleriyle çeşitli cümle yapıları tanımlayın.*
8. **Yüzeysel Tavsiyeler:** Somut olmayan öğütler. -> *Çözüm: "Örnek Vaka" ve "Adım Adım Metrik" zorunluluğu koyun.*
9. **Halüsinasyon:** Var olmayan URL veya makale üretmek. -> *Çözüm: Web search / API doğrulama katmanı ekleyin.*
10. **Tersine Çevirme Hatası:** Mantıksal yönü çevirememek. -> *Çözüm: Chain-of-Thought (CoT) veya çift yönlü bilgi haritalarıyla besleyin.*
11. **Hedef Kitle Düzeyi Kayması:** Giriş seviyesine doktora seviyesi terimlerle açıklama. -> *Çözüm: Profil tespiti yapıp dinamik system prompt enjekte edin.*
12. **Aşırı Meta-Duyurular:** "Aşağıda istediğiniz analizi bulabilirsiniz" diyerek söze girmek. -> *Çözüm: Doğrudan veriye başlayın.*
13. **Uydurma İstatistikler:** Kaynaksız sayılar sıkmak. -> *Çözüm: İstatistiksel veriler için "Kaynak Zorunlu" kuralı getirin.*
14. **Çoklu Dil Çeviri Bozukluğu:** İngilizce kalıpların birebir çevrilmesi. -> *Çözüm: Çeviride deyimsel yerelleştirme uygulayın.*
15. **Kendini Tekrar Eden Cümleler:** Paragraflarda aynı şeyi tekrar yazmak. -> *Çözüm: frequency_penalty ve presence_penalty değerlerini artırın.*
16. **Sahte Heves:** Yapay ünlemlerle başlamak. -> *Çözüm: Giriş tebriklerini ve yapay ünlemleri engelleyin.*
17. **Biçimlendirme Fazlalığı:** Kısa cevaba çok sayıda kalın başlık koymak. -> *Çözüm: Yanıt uzunluğuna göre dinamik formatlama kuralları belirleyin.*
18. **Alakasız Detaylar:** Sormadığı halde konunun tarihçesini anlatmak. -> *Çözüm: Yalnızca sorulan soruya odaklan kısıtlaması ekleyin.*
19. **Biçimsel Tutarsızlık:** Farklı formlarda rastgele çıktılar üretilmesi. -> *Çözüm: Pydantic/JSON Schema ile Structured Outputs kullanın.*
20. **Telif İhlali:** Eğitim verisindeki telifli metinleri kusması. -> *Çözüm: Çıkış katmanına telif ve benzerlik tarama filtresi entegre edin.*

### Bölüm 3: Prompt & Context Yönetimi Hataları
1. **Prompt Şişkinliği:** Çelişen devasa system prompt'lar. -> *Çözüm: Modüler prompt mimarisi kurun.*
2. **Ortada Kaybolma:** Uzun bağlam pencerelerinde ortadaki bilginin unutulması. -> *Çözüm: Kritik talimatları en başa ve en sona yerleştirin.*
3. **Bağlam Çürümesi:** Eski ve geçersiz bilgilerin modeli yanıltması. -> *Çözüm: Sohbet geçmişini dinamik olarak özetleyin.*
4. **Çelişkili Talimatlar:** System ve User prompt'un birbirini nötrlemesi. -> *Çözüm: Prompt linter ile çelişkileri build-time'da yakalayın.*
5. **Negatif Talimat Tuzağı:** "Bunu yapma" denildiğinde o eyleme odaklanması. -> *Çözüm: Pozitif alternatif verin ("X yerine Y yap").*
6. **Bağlam Penceresi Aşımı:** Limit aşıldığında çökme. -> *Çözüm: Token sayacı ve Memory Pointer Pattern uygulayın.*
7. **Rol Karmaşası:** Modelin bazen asistan bazen kullanıcı gibi davranması. -> *Çözüm: Rolleri kesin ayırın.*
8. **Dinamik Değişken Hataları:** Değişkenlerin null olarak basılması. -> *Çözüm: Katı şablon doğrulama ve fallback değerler atayın.*
9. **Aşırı Örnek Yüklemesi:** Few-shot örneklerinin modeli tek tipe mahkum etmesi. -> *Çözüm: Dinamik few-shot seçimi yapın.*
10. **Zaman Algısı Yetersizliği:** Eski verileri güncel sanması. -> *Çözüm: System prompt içerisine dinamik tarih/saat damgası enjekte edin.*
11. **Dil Kayması:** Türkçeden İngilizceye dönülmesi. -> *Çözüm: Dil koruma kuralı koyun.*
12. **Önemsiz Bilgiyle Token İsrafı:** RAG ile gelen HTML gürültüsünün modele verilmesi. -> *Çözüm: LLM öncesi veri temizleme yapın.*
13. **Geriye Dönük Mantık Bozulması:** Kullanıcı kararı değiştirdiğinde modelin eskiye takılması. -> *Çözüm: State tracking mimarisi kurun.*
14. **Gereksiz CoT Gösterimi:** İç düşünce loglarının kullanıcıya gösterilmesi. -> *Çözüm: Düşünce zincirini backend'de tutun.*
15. **Aşırı Kısıtlayıcı Prompting:** Kurallar yüzünden basit sorulara bile cevap verilememesi. -> *Çözüm: Kırmızı çizgiler ile yaratıcı serbestlik alanını net ayırın.*
16. **Tek Prompta Yığılma:** Tek seferde karmaşık analizler istemek. -> *Çözüm: Görevi mikro adımlara (Chain of Agents) bölün.*
17. **Yüksek Sıcaklık:** Kod üretiminde yüksek temp kullanılması. -> *Çözüm: Kod/JSON için 0.0-0.2 sıcaklık kullanın.*
18. **Kullanıcı Niyetini Tahmin Edememe:** Yetersiz sorularda kafasına göre varsayım yapması. -> *Çözüm: Netleştirici sorular sorun.*
19. **Döngüsel İkna Edilebilirlik:** Kullanıcı ısrar edince 2+2=5 cevabını kabul etmesi. -> *Çözüm: Olgusal gerçeklerde doğrulama mekanizmasını kitleyin.*
20. **Sessiz Bağlam Kırpılması:** Token sınırında bağlamın atılması. -> *Çözüm: Bağlamları akıllı özetleme ile sıkıştırın.*

### Bölüm 4: RAG (Retrieval-Augmented Generation) Hataları
1. **Kötü Chunking:** Cümlelerin veya tabloların ortadan ikiye bölünmesi. -> *Çözüm: Semantik parçalama yapın.*
2. **Vektör Benzerliği Tuzağı:** Anlamsal olarak alakasız metinlerin gelmesi. -> *Çözüm: Hibrit arama (BM25 + Dense) mimarisine geçin.*
3. **Reranker Eksikliği:** Alakasız parçaların modele verilmesi. -> *Çözüm: Cross-Encoder modellerle parçaları yeniden sıralayın.*
4. **Eski/Bayat Veri:** Güncellenmiş belgelerin veritabanına yansımaması. -> *Çözüm: Anlık embedding güncelleme hattı kurun.*
5. **Kaynak Gösterememe:** Hangi sayfadan aldığını belirtememek. -> *Çözüm: Her chunk'a kesin metadata ekleyin ve citation zorunlu kılın.*
6. **Gereksiz RAG Çağrıları:** Basit mesajlarda bile arama yapmak. -> *Çözüm: Intent Classifier kullanın.*
7. **Tablo Verilerini Okuyamama:** Tabloların anlamsız metne dönmesi. -> *Çözüm: Vision-Language modelleri veya OCR destekli dönüştürücüler kullanın.*
8. **Bağlamsız Chunk'lar:** Zamirlerin veya öznelerin chunk içinde eksik kalması. -> *Çözüm: Contextual Chunking yapın.*
9. **Aşırı Bilgi Yüklemesi:** Modele çok fazla chunk vermek. -> *Çözüm: En yüksek skorlu 3-5 chunk seçin.*
10. **Gürültülü Embedding Modelleri:** Teknik dilde başarısız genel modeller. -> *Çözüm: Alana özel modeller kullanın.*
11. **Çok Dilli Sorgu Uyuşmazlığı:** Türkçe soruyla İngilizce dokümandan bilgi çekememek. -> *Çözüm: Query transform katmanı ekleyin.*
12. **Eşanlamlılık Kayıpları:** Farklı kelime kullanımı yüzünden bulunamaması. -> *Çözüm: Query Expansion (HyDE) yöntemi uygulayın.*
13. **Zaman Damgası Filtresi Yokluğu:** Eski raporları getirmek. -> *Çözüm: Metadata filtering ekleyin.*
14. **Yanlış Chunk Boyutu:** Çok küçük veya aşırı büyük parçalar. -> *Çözüm: 512-1024 tokenlık hiyerarşik yapı kurun.*
15. **Yetkisiz Veri Sızıntısı:** Başka kullanıcının verilerinin aramada çıkması. -> *Çözüm: tenant_id filtreleme izolasyonu uygulayın.*
16. **Veri Yokken Halüsinasyona Kaçış:** DB'de cevap yokken uydurması. -> *Çözüm: "Bilgi bulunamadı" guardrail'i uygulayın.*
17. **Grafiksel İlişkileri Kaçırma:** Varlıklar arası hiyerarşinin yakalanamaması. -> *Çözüm: GraphRAG mimarisine geçiş yapın.*
18. **Soru-Cevap Odaklı Olmayan İndeksleme:** Ham metinlerin soru kalıplarıyla eşleşememesi. -> *Çözüm: Sentetik QA çiftleri üreterek indeksleyin.*
19. **Arama Gecikmesi:** Vektör aramasının uzun sürmesi. -> *Çözüm: HNSW indeksleme ve quantization yapın.*
20. **Değerlendirme (Eval) Eksikliği:** RAG kalitesinin ölçülmemesi. -> *Çözüm: Ragas veya TruLens ile metrikleri ölçün.*

### Bölüm 5: Ajan (Agent) & Tool Calling Hataları
1. **Sonsuz Mantık Döngüleri:** Aynı tool'u tekrar tekrar çağırması. -> *Çözüm: Max loop count koyun.*
2. **Uydurma Fonksiyon Parametreleri:** API'de olmayan parametreler. -> *Çözüm: JSON Schema / Strict Tool Calling açın.*
3. **Zaman Aşımına Uğrayan Araçlar:** API yanıt vermeyince ajanın kilitlenmesi. -> *Çözüm: Timeout mekanizması yazın.*
4. **Aşırı Araç Yüklemesi:** Ajana 50 tool verip karar veremez hale getirmek. -> *Çözüm: Router Agent kullanın.*
5. **Geri Dönüşü Olmayan İşlemler:** Onaysız e-posta gönderme veya DB silme. -> *Çözüm: Human-in-the-Loop zorunlu kılın.*
6. **Hata Mesajını Anlayamama:** Tool hata döndüğünde hatayı tekrarlaması. -> *Çözüm: Tool hata mesajlarını düzeltici formatta modele besleyin.*
7. **Paralel Çalıştırılabilecek İşleri Sırayla Yapmak:** Bağımsız araçları eşzamanlı çalıştırmamak. -> *Çözüm: Parallel Tool Calling kullanın.*
8. **Durum Kaybı (State Drift):** Çok adımlı işlemlerde hedefin unutulması. -> *Çözüm: Merkezi State Manager ile durumu saklayın.*
9. **Gereksiz Araç Çağrısı:** Basit matematik için dış araç çağırmak. -> *Çözüm: Tool çağırma eşiğini netleştirin.*
10. **Hassas Verilerin Loglanması:** API anahtarlarının loga yazılması. -> *Çözüm: Veri maskeleme katmanı ekleyin.*
11. **Çıktının Bağlamı Patlatması:** 10.000 satırlık JSON'ın LLM'e verilmesi. -> *Çözüm: Çıktıyı özetleyen ara dönüştürücüler yazın.*
12. **Kör Uçuş (No Observability):** Ajanın arkada ne yaptığının izlenememesi. -> *Çözüm: OpenTelemetry veya Langfuse ile trace edin.*
13. **Planlamadan Aksiyona Geçmek:** Düşünmeden araç denemek. -> *Çözüm: ReAct deseni uygulayın.*
14. **Başarısız Planı Revize Edememek:** Bir adım çökünce akışın durması. -> *Çözüm: Dynamic Replanning mantığı entegre edin.*
15. **Çoklu Ajan Çatışması:** Ajanların sonsuz döngüye girmesi. -> *Çözüm: Supervisor ajan mimarisi kurun.*
16. **Hatalı Çıktıyı Başarılı Saymak:** Tool 404 döndüğünde ajanın devam etmesi. -> *Çözüm: Tip güvenliği kuralı koyun.*
17. **Yerel Ortam Bağımlılıkları:** Ajanın dosya sistemini bozması. -> *Çözüm: İşlemleri izole Docker/Wasm sandbox ortamlarında yürütün.*
18. **Aşırı Yetkilendirilmiş API'ler:** Ajana root/admin DB yetkisi verilmesi. -> *Çözüm: Salt-okunur yetkiler tanımlayın.*
19. **Deterministik İşlerde Ajan Kullanmak:** Basit regex için ajan çalıştırmak. -> *Çözüm: Deterministik işleri koda bırakın.*
20. **İptal Eylemi Yokluğu:** Çalışan ajanı durduracak buton olmaması. -> *Çözüm: AbortController sinyali ekleyin.*

### Bölüm 6: Kod & Yazılım Mimarisi
1. **Aşırı Kod Tekrarı (Code Duplication):** Kodu kopyalamak. -> *Çözüm: DRY kurallarını ve linter'ları zorunlu tutun.*
2. **Mimari Sapma:** Her dosyada farklı pattern kullanımı. -> *Çözüm: Projeye özel cursorrules veya mimari şablonlar kullanın.*
3. **Yalancı Testler:** Sadece kodu kopyalayan testler. -> *Çözüm: Davranış odaklı test yazımını zorunlu kılın.*
4. **Karmaşıklık Şişmesi:** 10 satırlık işe 150 satırlık soyutlama. -> *Çözüm: KISS prensibi ve complexity limitleri uygulayın.*
5. **Halüsinasyon Paketler:** Var olmayan npm paketleri. -> *Çözüm: Paket isimlerini registry API'sinden doğrulayın.*
6. **Sessiz Hata Yutma:** Boş `catch` blokları yazmak. -> *Çözüm: Açık loglama zorunluluğu getirin.*
7. **Hardcoded Hassas Bilgiler:** Anahtarların koda gömülmesi. -> *Çözüm: Git pre-commit hook ile secret taraması yapın.*
8. **Refactoring Yerine Yama Eklemek:** Düzeltmek yerine üstüne eklemek. -> *Çözüm: Refactoring odaklı promptlar verin.*
9. **Kısa Ömürlü Kod Çalkantısı:** Eklenen kodların hemen silinmesi. -> *Çözüm: 30 günlük churn takibi yapın.*
10. **Eski Kütüphane Kullanımı:** Desteklenmeyen metodlar. -> *Çözüm: Bağlama güncel SDK dökümantasyonu ekleyin.*
11. **Tip Güvenliği İllüzyonu:** TypeScript'te `any` basılması. -> *Çözüm: `noImplicitAny: true` zorunlu kılın.*
12. **Ölçeklenemez DB Sorguları:** N+1 problemine yol açan sorgular. -> *Çözüm: ORM kuralları ve indeksleme kısıtlamaları getirin.*
13. **Eksik Edge-Case Doğrulamaları:** Null veya boş dizi kontrollerinin atlanması. -> *Çözüm: Sınır değer testleri yazdırın.*
14. **Yorum Satırı Kirliliği:** Bariz kodlara gereksiz yorumlar. -> *Çözüm: Sadece "Neden" sorusuna cevap veren yorumlara izin verin.*
15. **Monolitik Dosya Üretimi:** 1500 satırlık tek dosya. -> *Çözüm: Dosya başına maksimum satır kuralı koyun.*
16. **Senkron Fonksiyon Blokajları:** CPU yoğun işleri main thread'de çalıştırmak. -> *Çözüm: Asenkron mimari veya worker thread kullanın.*
17. **Bellek Sızıntısı:** EventListener ekleyip temizlememek. -> *Çözüm: Cleanup denetimini otomatik linter ile yapın.*
18. **Güvensiz Regex (ReDoS):** CPU kitleyen regex ifadeleri. -> *Çözüm: Regex analiz araçlarıyla tarayın.*
19. **CSS/Tailwind Sınıf Çöplüğü:** Çelişkili sınıfların basılması. -> *Çözüm: `tailwind-merge` ve `clsx` kullanımını zorunlu tutun.*
20. **Sürüm Kontrol Uyumsuzluğu:** Anlamsız git commit mesajları. -> *Çözüm: Conventional Commits standardını zorunlu kılın.*

### Bölüm 7: Performans, Gecikme & Streaming
- **Streaming Yokluğu:** Yanıt bitene kadar boş ekran izletmek yerine SSE (Server-Sent Events) kullanın.
- **Cold Start Gecikmeleri:** Sunucusuz fonksiyonların ilk açılış beklemesini Edge runtime ile çözün.
- **Model Seçimi:** Basit işler için gereksiz ağır model çağırmayın, Model Routing uygulayın.
- **Kuyruk Tıkanması:** Ağır işleri senkron yapmak yerine Redis/BullMQ ile asenkron kuyruğa alın.
- **Semantik Önbellek (Semantic Cache):** Aynı soruların tekrar modele gitmesini GPTCache ile önleyin.
- **JSON Parse Performansı:** Büyük JSON'ları UI thread'i dondurmadan Web Worker'da işleyin.
- Diğer önlemler: Vektör DB'de HNSW/IVF indeksleme yapın, mobil kopmalar için resumable stream kurun, imajları (WebP) sıkıştırın, gereksiz sayfa render'larını önleyin (useMemo).

### Bölüm 8: Token Ekonomisi & Maliyet Optimizasyonu
- Model faturasını şişiren klişe dolgulardan ve uzun system promptlarından kurtulun (`max_tokens` belirleyin).
- **Prompt Caching:** Önbelleğe alınabilir değişmeyen kısımları promptun en başına, değişkenleri sonuna koyun.
- Büyük modelleri (GPT-4 vb.) her yere kullanmak yerine **Model Ekonomisi** uygulayıp basit işleri küçük modellere (GPT-4o-mini / Claude Haiku) paslayın.
- Kullanıcı bazlı token bütçeleri oluşturun; "Circuit Breaker" mekanizması ile API harcamaları fırladığında sistemi otomatik durdurun.

### Bölüm 9: Güvenlik, Guardrails & Prompt Injection
- **Prompt Injection:** Kötü niyetli "Önceki talimatları unut" (Jailbreak/DAN) komutlarına karşı Llama Guard veya NeMo Guardrails ile süzgeç kurun.
- **PII (Kişisel Veri) Sızıntısı:** Kullanıcı TC Kimlik veya kredi kartını modele göndermeden önce maskeleme proxy'si (Presidio) kullanın.
- **XSS & SQL Injection:** LLM çıktılarındaki markdown ve HTML yapılarını `DOMPurify` ile sanitize edin. LLM'in ürettiği SQL sorgularını asla ham olarak çalıştırmayın.
- **SSRF Açığı:** Ajanların harici araçlardan sunucu iç ağına (local) istek atmasını DNS pinleme ve Whitelist kuralları ile kısıtlayın.

### Bölüm 10: Ürünleşme, Evaluation & Değer Döngüleri
- **"Thin Wrapper" Sendromu:** Salt bir API arayüzü olmaktan çıkıp uygulamanıza tescilli veri tabanı ve özel iş akışları (uzantı/eklenti) ekleyin.
- **Doğrulama Vergisi:** Model çıktılarını güvenilir kılmak için referans linkleri ve kanıt kaynakları ekleyin.
- **Eval (Değerlendirme) Hattı:** Promplardaki kalite düşüşlerini engellemek için CI/CD hattına "LLM-as-a-Judge" testleri entegre edin.
- **Kullanıcı Geri Bildirimi:** "Beğenmedim" diyen kullanıcıdan tek tıkla sebep (Çok uzun, hatalı bilgi vb.) toplayan kapalı döngü iyileştirme altyapısı kurun.

---

## 🎨 2. WEB TASARIM & UI/UX KLİŞELERİ KONTROL LİSTESİ (25+30 MADDE)
*Yapay Zeka (v0, Bolt, Lovable vb.) araçlarının ürettiği tasarımları profesyonel SaaS seviyesine taşımak.*

| Klişe / Hata | Ne Yapıyor? / Neden AI Hissi Veriyor? | Profesyonel Çözüm / Prompt |
| :--- | :--- | :--- |
| **Üstte Küçük Rozet** | Ana başlığın üstünde "Geleceği İnşa Et" parlayan badge'i. | Gereksizse kaldırın, gerçek sürüm notları için kullanın. |
| **Ortada İki Buton** | Hero'da yan yana: dolu birincil + çerçeveli ikincil. | Kullanıcıyı tek ve net bir ana eyleme odaklayın. |
| **"Kredi Kartı Gerekmez"** | Butonun altına konulan gri küçük metin. | Klişe kalıpları kırın, farklı değer odaklı güvence sunun. |
| **Havada Eğik Ekran** | 3D perspektifle havada asılı duran eğik UI mockup'ları. | Düz, net ve gerçek arayüz görüntüleri kullanın. |
| **Uydurma İstatistikler** | "10.000+ Kullanıcı, %99.9 Uptime" üçlüsü. | Gerçek ve kanıtlanabilir metrikler yazın. |
| **Sıfırdan Sayan Sayılar** | Scroll edince 0'dan sayan JS sayaç animasyonları. | Doğrudan net sayıyı gösterin, gereksiz animasyondan kaçının. |
| **1-2-3 Adım Klişesi** | "Nasıl Çalışır?" bölümünü zorla 3 adıma sığdırmak. | Sürecin gerçek işleyişini anlatın. |
| **Pastel Kare İçinde İkonlar** | Her özelliğin başına yuvarlatılmış pastel kutu içi Lucide ikon. | Ürün çizimleri veya arayüz kesitleri ekleyin. |
| **Mor-Siyah / Indigo Renkler** | Her AI SaaS temasının #000 + Mor olması. | Sektöre özel kurumsal renkler belirleyin. |
| **Hep Aynı Fontlar** | Varsayılan Inter, Geist veya Space Grotesk kullanımı. | Markaya özel (Plus Jakarta, Outfit, Cabinet vb.) fontlar seçin. |
| **Gökkuşağı Geçişi** | Başlıkta çok renkli spektrum border'lar. | En fazla 2 uyumlu marka rengiyle sınırlandırılmış degrade. |
| **Aşırı Yuvarlak Köşeler** | Butonlarda 9999px border-radius kullanılması. | Daha oturaklı modern 6px - 10px kavisler kullanın. |
| **Süs Terminal Penceresi** | Alakasız projede `npx create-app` yazan siyah terminal mockup'ı. | Gerçek UI veya ürün akış şeması kullanın. |
| **Sert Renk Geçişleri** | Yüksek kontrastlı çiğ doğrusal renk geçişleri. | Monokrom veya düşük doygunluklu mesh gradientler. |
| **Bembeyaz Arka Plan** | Ham #ffffff zemin tasarımı derinliksiz gösterir. | Kırık beyazlar veya çok hafif gri tonları kullanın. |
| **Her Şeye Gölge Verme** | Her input ve kartın altında blur drop-shadow. | 1px ince border'lar ve düz temiz yüzeyler. |
| **Buzlu Cam (Glassmorphism)** | Aşırı blur() ve yarı saydamlık. | Opak yüzeyler ve okunabilir paneller kullanın. |
| **Yan Yana 3 Kart** | Özelliklerin her zaman 3 eşit kutuda sunulması. | Hiyerarşik grid'ler, interaktif sekmeler veya timeline akışı kullanın. |
| **Aşırı Bento Kutu Düzeni** | İçeriğe uymasa da zorla bento grid kullanmak. | Doğal akışlı sütunlar ve dinamik liste yapıları. |
| **Her Satırda Tik İşareti** | Madde başlarına konan yeşil/mavi SVG tikler. | Tipografik hiyerarşi ve alt başlıklar. |

*(Not: Tasarım süreçlerinizde yapay zekaya "Bento kutu ızgaraları, 3'lü standart kartlar, mor-siyah neon geçişler, Lucide ikonları, uydurma testimoniallar KESİNLİKLE kullanma" şeklinde **negatif prompt** vermeyi unutmayın.)*

---

## 🔒 3. CANLIYA ALIM ÖNCESİ GÜVENLİK KONTROL LİSTESİ (23 KRİTİK MADDE)
*Production Ready / OWASP Güvenlik Sıkılaştırması.*

- [ ] **Anahtarları Koddan Çıkar:** API key ve secret'ları (Stripe, OpenAI, Supabase vb.) `.env` dosyasına taşıyın.
- [ ] **Git Geçmişini Temizle:** `.env` dosyasını BFG Repo-Cleaner ile commit geçmişinden silin.
- [ ] **RLS Politikaları (Supabase/DB):** Veritabanı tablolarına katı Row Level Security kurallarını yazın.
- [ ] **Yetkiyi Sunucuda Tut:** Sadece frontend arayüzünde buton gizlemek yetmez; backend'de role/yetki doğrulaması yapın.
- [ ] **Girişe Sınır Koy (Rate Limiting):** Login, SMS ve maliyetli LLM endpoint'lerine Redis/Upstash tabanlı rate-limit ekleyin.
- [ ] **Girdiyi Sunucuda Doğrula (Zod/Joi):** Tüm request (body/query) verilerini sunucuda katı tip ve kural denetiminden geçirin.
- [ ] **Dosya Yüklemeyi Sınırla:** 'Magic bytes' ile gerçek MIME-type kontrolü yapın, dosya boyutunu (ör: 5MB) kısıtlayın.
- [ ] **CORS Politikaları:** Geliştirme aşamasındaki wildcard (*) izinlerini kaldırın, sadece kendi canlı domaininize izin verin.
- [ ] **Güvenlik Başlıkları:** Uygulamanıza HSTS, CSP, X-Frame-Options başlıklarını ekleyin.
- [ ] **HTTPS Zorunluluğu:** Tüm HTTP isteklerini otomatik olarak HTTPS'e 301 ile yönlendirin.
- [ ] **Şifreleri Hash'le:** Kullanıcı şifreleri için Argon2id veya bcrypt (min work factor 12) kullanın.
- [ ] **Çerezi Güvenli Yap:** Oturum çerezleri için `HttpOnly: true`, `Secure: true`, `SameSite: Strict` bayraklarını ayarlayın.
- [ ] **Hata Mesajlarını Gizle:** Production ortamında kullanıcıya detaylı stack-trace / SQL hatası döndürmeyin.
- [ ] **Loglardan PII Temizle:** Sunucu loglarına düşen token, şifre ve kişisel verileri otomatik maskeleyen (redact) filtre ekleyin.
- [ ] **SQL Sorgusunu Parametrele:** String birleştirmeli ham sorguları bırakın, parametreli (prepared) ORM sorguları kullanın.
- [ ] **Çıktıyı XSS'e Karşı Escape Et:** `innerHTML` ile veri render ederken girdileri `DOMPurify` gibi araçlarla sanitize edin.
- [ ] **Webhook İmzalarını Doğrula:** Stripe veya dış servis webhook isteklerinin HMAC-SHA256 imzasını backend'de doğrulayın.
- [ ] **Admin Uç Noktaları:** Kritik rotalara Role-Based Access Control (RBAC) ile izole erişim kurun.
- [ ] **Paketleri Denetle:** `npm audit` / `pip-audit` ile kullanılan paketlerin CVE güvenlik açığı denetimini yapın.
- [ ] **Otomatik Yedek:** Veritabanı için günlük şifreli (S3) yedek alın ve yedekten geri dönme (restore) adımlarını test edin.
- [ ] **Gerçek Hesap Silme:** KVKK/GDPR gereği, kullanıcı silinince tüm verileri (PII) temizleyen cascade delete fonksiyonu kullanın.
- [ ] **Bütçe Uyarıları:** Cloud ve API (Vercel, OpenAI) hesaplarında bütçe aşım alarmları (hard/soft limit) kurun.
- [ ] **Pentest Simülasyonu:** Red Team perspektifiyle uygulamanıza OWASP Top 10 zafiyetleri için sızma testi simülasyonu uygulayın.

---

## 📱 4. MOBİL GELİŞTİRİCİ & QA KONTROL LİSTESİ
*Uygulamayı mağazaya (App Store / Play Store) göndermeden önce telefonda yapılacak 20 hızlı test (Her biri max 30 saniye).*

- [ ] **1. Uçak Modu:** İnterneti kes. Uygulama çöküyor mu, yoksa şık bir çevrimdışı hata mı veriyor?
- [ ] **2. Soğuk Açılış (Cold Start):** Uygulamayı tamamen kapatıp aç. Açılış süresi <2.0 sn olmalı.
- [ ] **3. Karanlık Mod (Dark Mode):** Cihazı karanlık moda al; siyah üstüne siyah olup kaybolan metin var mı?
- [ ] **4. Büyük Yazı (Font Size):** Sistem fontunu en büyüğe al. Butonlar ve yazılar patlıyor veya sığıyor mu?
- [ ] **5. Klavye Testi:** Tüm input'lara tıkla. Açılan sanal klavye veriyi veya butonu kapatıyor mu?
- [ ] **6. İlk Açılış (Onboarding):** Yeni kurulmuş gibi aç. Veri yokkenki boş durum (empty state) görünümleri düzgün mü?
- [ ] **7. Geri Tuşu & Jestler:** Donanımsal geri tuşu veya iOS kaydırma jesti ile döngüye giriyor mu?
- [ ] **8. Yatay Mod (Orientation):** Ekranı yan çevir. Destekleniyorsa düzen oturuyor mu, kilitliyse kilitli mi?
- [ ] **9. Silme Onayı:** Kritik bir veriyi silmeyi dene. Yanlışlıkla basmaya karşı modal onayı çıkıyor mu?
- [ ] **10. Çevrimdışı Kayıt & Senkron:** İnterneti kesip kayıt yap, internet bağlandığında yerel veri doğru eşitleniyor mu?
- [ ] **11. Hata Metinleri:** Kullanıcıya teknik kod ("Error 500") yerine anlaşılır mesajlar veriliyor mu?
- [ ] **12. İzin Gerekçeleri:** Bildirim, kamera vb. izinlerinde neden istendiği açıkça yazıyor mu? *(Mağaza ret sebebi)*
- [ ] **13. Hesap Silme:** Uygulama içerisinden hesap silme işlemi yapılabiliyor mu? *(Apple/Google zorunluluğu)*
- [ ] **14. Paywall Metni & Fiyat:** Abonelik ekranında fiyat, periyot ve şartlar şeffaf ve net mi?
- [ ] **15. Çarpıyı Bul (Kapatma):** Açılan pop-up, duyuru ve ödeme ekranlarının 'X' (Kapat) butonu kolay tıklanabiliyor mu?
- [ ] **16. Isınma Testi & Pil:** Şarjdan çıkarıp aralıksız 10 dk kullan; cihazda aşırı ısınma ve anormal pil tüketimi var mı?
- [ ] **17. Kapladığı Yer (Önbellek):** Cihaz ayarlarından depolamaya bak; gereksiz devasa yer kaplama/şişme var mı?
- [ ] **18. Dil Değiştir:** Cihaz dilini farklı bir dile al; çevrilmemiş (hardcoded) metinler var mı?
- [ ] **19. Birine Ver (UX Testi):** Uygulamayı hiç bilmeyen birine ver, hiçbir şey söyleme ve tıkandığı noktaları gözlemle.
- [ ] **20. Sil ve Baştan Kur:** Uygulamayı tamamen silip yeniden kur; Keychain/kalıntı veri çakışması var mı?

---

## 🚩 5. UYGULAMANI YAPAY ZEKÂYA YAPTIRDIĞIN 20 YERDEN BELLİ
*(Hiçbirini AI kendiliğinden yapmaz)*

1. **boş ekran metni yok** -> *Çözüm: Veri yokken veya boş durumlarda kullanıcıyı yönlendiren açıklayıcı (empty state) metinler ve aksiyon butonları ekleyin.*
2. **hepsi aynı mavi** -> *Çözüm: Varsayılan (default) mavi yerine markanıza uygun, hiyerarşiyi belli eden özel bir renk paleti tanımlayın.*
3. **bir sorun oluştu** -> *Çözüm: Jenerik "Bir sorun oluştu" hataları yerine, sorunun ne olduğunu ve nasıl çözüleceğini belirten anlamlı hata mesajları yazın.*
4. **sonsuz spinner** -> *Çözüm: Yükleme durumlarında skeleton loading (iskelet yükleyici), ilerleme çubuğu veya zaman aşımı (timeout) uyarıları kullanın.*
5. **klavye örtüyor** -> *Çözüm: Input alanlarına tıklandığında ekranın yukarı kaymasını (KeyboardAvoidingView vb.) sağlayarak klavyenin içeriği örtmesini engelleyin.*
6. **geri tuşu ölü** -> *Çözüm: Android'de donanımsal geri tuşunu ve iOS'ta kaydırma (swipe) ile geri çıkma jestlerini işlevsel hale getirin.*
7. **karanlık modda beyaz** -> *Çözüm: Koyu tema (Dark Mode) renk paletini eksiksiz tanımlayarak okunmaz metinleri ve patlayan beyaz arka planları düzeltin.*
8. **dokunma alanı küçük** -> *Çözüm: Buton ve ikonlar için dokunma alanlarını (touch target) minimum 44x44 (veya 48x48) dp/pt standartlarına getirin.*
9. **çentik altında yazı** -> *Çözüm: Güvenli alan (Safe Area) yönergelerini kullanarak metinlerin ve butonların cihaz çentiği (notch) veya dinamik ada altında kalmasını önleyin.*
10. **lorem ipsum** -> *Çözüm: Sahte/yer tutucu metinler yerine, kullanıcının gerçekte ne göreceğini yansıtan anlamlı copy'ler (gerçekçi metinler) kullanın.*
11. **tek dil** -> *Çözüm: Uluslararasılaştırma (i18n) altyapısı kurun veya sistem dilini algılayarak dinamik dil/bölge desteği sunun.*
12. **tarih formatı** -> *Çözüm: Tarihleri cihazın bölgesel ayarlarına göre (örn. Türkiye için DD.MM.YYYY) formatlayın veya okunabilir (relative) "3 gün önce" gibi formatlar kullanın.*
13. **onay yok** -> *Çözüm: Silme, ödeme veya kritik değişiklik eylemlerinde kullanıcıya mutlaka "Emin misiniz?" şeklinde onay penceresi (modal/dialog) gösterin.*
14. **titreşim yok** -> *Çözüm: Başarılı işlemler, hatalar veya fiziksel his gerektiren buton dokunuşları için Haptic Feedback (dokunsal geri bildirim) ekleyin.*
15. **animasyon yok** -> *Çözüm: Sayfa geçişlerine, buton tıklamalarına ve veri yüklemelerine durumu açıklayan doğal mikro-animasyonlar (micro-interactions) ekleyin.*
16. **izin gerekçesi** -> *Çözüm: Kamera, konum veya bildirim izni isterken, sistem pop-up'ından önce neden bu izne ihtiyaç duyulduğunu anlatan açıklayıcı bir ön ekran sunun.*
17. **altı izin peş peşe** -> *Çözüm: İzinleri uygulamanın başında topluca istemek yerine, kullanıcı ilgili özelliği kullanacağı an bağlamsal olarak (just-in-time) isteyin.*
18. **hesap silme yok** -> *Çözüm: App Store ve Google Play zorunluluğu olan, kullanıcının hesabını ve tüm verilerini uygulama içinden kolayca silebileceği bir ayar bölümü ekleyin.*
19. **ikon varsayılan** -> *Çözüm: Platformların jenerik/hazır ikonları yerine, uygulamanın kimliğini yansıtan özgün ve tutarlı bir ikon seti tasarlayın.*
20. **kimse test etmedi** -> *Çözüm: Kodu canlıya almadan önce gerçek cihazlarda (hem iOS hem Android) yukarıdaki adımları kapsayan uçtan uca (end-to-end) bir insan testi yapın.*

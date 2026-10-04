# Web Projesi Canlıya Alma Kontrol Listesi (Production-Ready Checklist)

> Vibe-coding prototipini gerçek, güvenilir ve yayına hazır profesyonel bir web ürününe dönüştüren 20 temel gereksinim.

---

## 1. UI / UX, Etkileşim ve Dönüşüm (CRO)

- [ ] **01. Custom 404 Page (Özel 404 Hata Sayfası)**  
  Varsayılan sunucu hatası yerine kullanıcıyı anasayfaya veya arama kutusuna yönlendiren samimi, marka diline uygun sayfa.

- [ ] **02. CTA Above the Fold (İlk Ekranda Harekete Geçirici Mesaj)**  
  Kullanıcı sayfayı aşağı kaydırmadan doğrudan görünen, net bir değer önerisi ve belirgin aksiyon/kayıt butonu.

- [ ] **10. Mobile Breakpoints (Duyarlı / Responsive Ekran Düzeni)**  
  Mobil, tablet ve geniş masaüstü ekranlarında yatay taşma (`overflow-x`) olmayan, akıcı CSS medya sorguları.

- [ ] **11. Sticky Mobile CTA (Mobilde Sabit Kalan Aksiyon Butonu)**  
  Mobil ekranlarda sayfa kaydırıldıkça ekranın altında sabit kalarak dönüşüm kaybını önleyen aksiyon çubuğu.

- [ ] **12. Loading States (Yüklenme Bildirimleri)**  
  Veri çekilirken veya buton tıklandığında beliren spinner, skeleton ekranlar ve donma hissini engelleyen görsel geri bildirimler.

- [ ] **13. Form Error States (Form Doğrulama ve Hata Durumları)**  
  Eksik veya hatalı alanlarda kullanıcı dostu inline uyarılar, kırmızı kenarlıklar ve anlaşılır düzeltme mesajları.

- [ ] **14. Thank-you Page (Teşekkür / Dönüşüm Sayfası)**  
  Form gönderimi veya satın alma sonrası işlemi teyit eden, sonraki adımları aktaran ve analitik conversion event'lerini tetikleyen sayfa.

---

## 2. SEO, İndekslenme ve Sosyal Paylaşım

- [ ] **03. Meta Title Per Page (Sayfa Başına Özel Başlık)**  
  Her alt sayfa için optimize edilmiş, anahtar kelime ve marka içeren dinamik `<title>` etiketi.

- [ ] **04. Meta Description Per Page (Sayfa Başına Özel Açıklama)**  
  Google arama sonuçlarında (SERP) tıklama oranını (CTR) artıran 140-160 karakterlik özet açıklamalar.

- [ ] **05. Open Graph Image (OG / Sosyal Medya Önizleme Görseli)**  
  Twitter, WhatsApp, LinkedIn paylaşımlarında çıkan 1200x630px boyutunda profesyonel marka önizleme kartı.

- [ ] **06. Favicon Set (Tüm Platformlar İçin Favicon Paketi)**  
  `favicon.ico` (32x32), `apple-touch-icon.png` (180x180) ve `site.webmanifest` ikonlarını içeren eksiksiz set.

- [ ] **07. robots.txt (Arama Motoru Tarama Kuralları)**  
  Botlara hangi sayfaların taranıp taranmayacağını bildiren ve sitemap yolunu tanımlayan kök dizin dosyası.

- [ ] **08. sitemap.xml (Site Haritası)**  
  Tüm canlı sayfaları listeleyen ve Google Search Console'a iletilen güncel XML site haritası.

- [ ] **09. Alt Text on Every Image (Görsel Alternatif Metinleri)**  
  Ekran okuyucular (erişilebilirlik) ve görsel SEO için tüm `<img>` etiketlerinde açıklayıcı `alt` özniteliği.

---

## 3. Hukuki Uyumluluk, Güven ve Altyapı

- [ ] **15. Privacy Policy Page (Gizlilik Politikası / KVKK / GDPR)**  
  Kullanıcı verilerinin nasıl işlendiğini, saklandığını ve üçüncü partilerle paylaşımını açıklayan yasal metin.

- [ ] **16. Terms & Conditions (Kullanım Şartları ve Koşulları)**  
  Hizmet sınırlarını, telif haklarını, sorumluluk reddini ve kullanıcı yükümlülüklerini belirten yasal sözleşme.

- [ ] **17. Cookie Banner (Çerez Onay Bildirimi)**  
  Ziyaretçilere analitik ve pazarlama çerezlerini kabul/reddetme imkanı tanıyan mevzuata uygun onay bandı.

- [ ] **18. Analytics Installed (Web Analitik ve Etkinlik Takibi)**  
  Trafik, hemen çıkma oranı ve dönüşüm hunisini takip eden araç entegrasyonu (GA4, PostHog, Plausible vb.).

- [ ] **19. Real Contact Address (Gerçek İletişim & Şirket Bilgileri)**  
  Spam filtrelerini ve güven şüphelerini aşmak için gerçek fiziki adres, kurumsal domain e-postası ve iletişim formu.

- [ ] **20. Custom Domain, SSL & Security Headers (Özel Domain ve Güvenlik)**  
  Özel domain yapılandırması, zorunlu HTTPS/SSL sertifikası, CSP ve HSTS güvenlik başlıkları.
# CARVIS Hibrit Strateji - Implementation Roadmap

**Proje**: Carvis - Araç Yedek Parça & Servis Platformu  
**Strateji**: Hibrit (Marketplace + Teklif Sistemi + AI)  
**Başlangıç**: 24 Ocak 2026  
**Durum**: 🟡 In Progress

---

## 🎯 GENEL HEDEF

Bireysel araç sahipleri, parça tedarikçileri, ustalar ve çekiciler için **teklif bazlı** bir platform oluşturmak.

**Gelir Modeli**: %5-7 komisyon (sadece satıcılardan, teklif + randevu bazlı)  
**Ödeme**: PayTR  
**Hedef Kitle**: Tüm Türkiye  
**Platform**: Web + React Native (iOS + Android)

---

## ✅ TAMAMLANAN ÖZELLIKLER

### **Sprint 1: Altyapı & Realtime** (24 Ocak 2026)
- [x] Supabase migration (quotes, appointments, messages, notifications)
- [x] RLS politikaları
- [x] Realtime subscriptions
- [x] QuoteContext (teklif yönetimi)
- [x] NotificationContext (bildirimler + realtime)
- [x] QuoteCard bileşeni
- [x] NotificationScreen
- [x] QuotesScreen (tüm teklifler)
- [x] CustomerHome teklif listesi entegrasyonu
- [x] Bildirim badge'i (AppHeader)

---

## 🚧 DEVAM EDEN SPRINT

### **Sprint 2: Müşteri & Satıcı Akışları** (Şimdi)

#### **Faz 1: Test Verisi & Temel Akışlar** (1-2 saat)
- [ ] Test verisi oluşturma (SQL script)
- [ ] QuoteDetailScreen (teklif detayları + kabul/red)
- [ ] ServiceRequestForm (yeni talep oluşturma)
- [ ] SellerDashboard güncelleme (gelen talepler)
- [ ] CreateQuoteForm (teklif oluşturma)

#### **Faz 2: Mesajlaşma & Randevu** (2-3 saat)
- [ ] MessageContext (mesajlaşma yönetimi)
- [ ] MessageScreen (satıcı-müşteri chat)
- [ ] AppointmentContext (randevu yönetimi)
- [ ] AppointmentScreen (randevu oluşturma/görüntüleme)
- [ ] Randevu bildirimleri

#### **Faz 3: Satıcı Profil & Yönetim** (1-2 saat)
- [ ] SellerProfileScreen (uzmanlıklar, puanlama, portföy)
- [ ] SellerOrderManagement (sipariş yönetimi)
- [ ] Satıcı istatistikleri (kazanç, teklif sayısı)
- [ ] Puanlama sistemi (müşteri yorumları)

---

## 📅 GELECEK SPRINTLER

### **Sprint 3: Ödeme Sistemi (PayTR)** (3-4 saat)
- [ ] PayTR API entegrasyonu
- [ ] Ödeme formu (iframe)
- [ ] 3D Secure desteği
- [ ] Webhook handling (ödeme onayı)
- [ ] Komisyon hesaplama fonksiyonu
- [ ] Satıcı bakiye yönetimi
- [ ] Ödeme talepleri (partner → Carvis)
- [ ] Ödeme geçmişi

### **Sprint 4: WhatsApp Otomasyon** (2-3 saat)
- [ ] WhatsApp Business API setup (Twilio/360dialog)
- [ ] Mesaj şablonları (davet, teklif, sipariş güncellemesi)
- [ ] Toplu mesaj gönderimi
- [ ] Otomatik bildirimler (yeni teklif, sipariş durumu)

### **Sprint 5: Arama & Filtreleme** (2-3 saat)
- [ ] Parça arama (kategori, marka, model)
- [ ] Usta arama (konum, uzmanlık, marka)
- [ ] Teklif filtreleme (fiyat, teslimat süresi, garanti)
- [ ] Sıralama (fiyat, puan, teslimat)

### **Sprint 6: Fotoğraf & Medya** (1-2 saat)
- [ ] Supabase Storage setup
- [ ] Fotoğraf yükleme (araç, parça, servis)
- [ ] Görsel galerisi
- [ ] Profil fotoğrafı

### **Sprint 7: Konum Bazlı Özellikler** (2-3 saat)
- [ ] Konum izni (browser + native)
- [ ] Yakındaki ustalar (harita görünümü)
- [ ] Mesafe hesaplama
- [ ] Konum bazlı filtreleme

### **Sprint 8: React Native App** (1-2 hafta)
- [ ] Expo setup
- [ ] Shared API client (web ile ortak)
- [ ] Navigation (React Navigation)
- [ ] Core screens (Home, Quotes, Profile)
- [ ] Push notifications (Expo Notifications)
- [ ] Kamera (araç fotoğrafı)
- [ ] Konum servisleri
- [ ] iOS build
- [ ] Android build

### **Sprint 9: AI Bakım Önerileri (Option C)** (1 hafta)
- [ ] OpenAI API entegrasyonu
- [ ] Bakım geçmişi analizi
- [ ] Tahmine dayalı bakım önerileri
- [ ] Parça önerileri
- [ ] Maliyet tahmini

### **Sprint 10: Admin Panel** (1 hafta)
- [ ] Admin dashboard
- [ ] Kullanıcı yönetimi
- [ ] Partner onboarding (doğrulama)
- [ ] İstatistikler (GMV, komisyon, kullanıcı sayısı)
- [ ] Raporlama

---

## 🎯 MVP (Minimum Viable Product) Kapsamı

**Hedef**: İlk 100 kullanıcı + 20 partner

### **Temel Özellikler (Zorunlu)**
1. ✅ Kullanıcı kaydı & girişi
2. ✅ Araç ekleme
3. ✅ Servis talebi oluşturma
4. ✅ Teklif görüntüleme
5. ✅ Teklif kabul/red
6. ✅ Bildirimler (realtime)
7. ⏳ Satıcı teklif oluşturma
8. ⏳ Mesajlaşma
9. ⏳ Randevu yönetimi
10. ⏳ Ödeme (PayTR)

### **İkincil Özellikler (Nice to Have)**
- Arama & filtreleme
- Fotoğraf yükleme
- Konum bazlı usta bulma
- WhatsApp otomasyon
- AI bakım önerileri

### **Gelecek Özellikler**
- React Native app
- Admin panel
- Puanlama sistemi
- Kampanya yönetimi

---

## 📊 İLERLEME TAKIBI

| Sprint | Durum | Tamamlanma | Süre |
|--------|-------|------------|------|
| Sprint 1: Altyapı | ✅ Tamamlandı | 100% | 4 saat |
| Sprint 2: Akışlar | 🟡 Devam Ediyor | 20% | - |
| Sprint 3: Ödeme | ⏳ Beklemede | 0% | - |
| Sprint 4: WhatsApp | ⏳ Beklemede | 0% | - |
| Sprint 5: Arama | ⏳ Beklemede | 0% | - |
| Sprint 6: Medya | ⏳ Beklemede | 0% | - |
| Sprint 7: Konum | ⏳ Beklemede | 0% | - |
| Sprint 8: Native | ⏳ Beklemede | 0% | - |
| Sprint 9: AI | ⏳ Beklemede | 0% | - |
| Sprint 10: Admin | ⏳ Beklemede | 0% | - |

**Toplam İlerleme**: 10% (1/10 sprint tamamlandı)

---

## 🚀 SONRAKİ ADIMLAR

### **Şimdi (Sprint 2 - Faz 1)**
1. Test verisi oluştur (SQL)
2. QuoteDetailScreen implement et
3. ServiceRequestForm oluştur
4. SellerDashboard güncelle
5. CreateQuoteForm ekle

### **Bugün İçinde (Sprint 2 - Faz 2)**
6. MessageContext + MessageScreen
7. AppointmentContext + AppointmentScreen

### **Yarın (Sprint 2 - Faz 3)**
8. SellerProfileScreen
9. SellerOrderManagement
10. Puanlama sistemi

### **Bu Hafta (Sprint 3)**
11. PayTR entegrasyonu
12. Komisyon sistemi

---

## 📝 NOTLAR

- **Öncelik**: MVP özellikleri (1-10)
- **Test**: Her sprint sonunda manuel test
- **Deploy**: MVP tamamlandıktan sonra staging'e deploy
- **Feedback**: İlk 10 kullanıcıdan feedback topla

---

**Son Güncelleme**: 24 Ocak 2026, 23:26  
**Güncelleyen**: Antigravity AI

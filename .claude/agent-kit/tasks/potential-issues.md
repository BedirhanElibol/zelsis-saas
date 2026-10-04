# CARVIS - POTANSİYEL SORUNLAR VE ÇÖZÜMLERİ

**Tarih**: 25 Ocak 2026, 00:15  
**Durum**: Test ve Düzeltme Aşaması

---

## 🔴 KRİTİK SORUNLAR

### **1. MessageContext - Seller Profil Bilgisi Eksik**

**Sorun**: MessageContext'te mesajlar çekilirken seller profil bilgileri (company_name, seller_rating) join edilmemiş.

**Etki**: MessageScreen'de satıcı bilgileri görünmeyebilir.

**Çözüm**: QuoteContext'teki gibi profiles tablosunu join et.

**Dosya**: `src/context/MessageContext.jsx`

---

### **2. AppointmentContext - Vehicle Join Eksik**

**Sorun**: AppointmentContext'te vehicle bilgisi select'te var ama fetchAppointments'ta join edilmemiş olabilir.

**Etki**: Randevu ekranında araç bilgileri görünmeyebilir.

**Çözüm**: Vehicle join'i doğrula.

**Dosya**: `src/context/AppointmentContext.jsx`

---

### **3. ServiceRequestCard - Navigation Hatası**

**Sorun**: ServiceRequestCard'da `/seller/quote-create/${request.id}` rotası kullanılıyor ama bu rota seller dashboard içinde olmalı.

**Etki**: Satıcı teklif oluşturma sayfasına gidemeyebilir.

**Çözüm**: Rota yapısını kontrol et.

**Dosya**: `src/components/ServiceRequestCard.jsx`

---

### **4. QuoteCard - Seller ID Eksik**

**Sorun**: QuoteCard'da seller_id bilgisi olmayabilir, bu yüzden mesaj butonuna tıklandığında hata verebilir.

**Etki**: Mesaj ekranına geçiş yapılamaz.

**Çözüm**: QuoteContext'te seller_id'nin döndüğünü doğrula.

**Dosya**: `src/components/QuoteCard.jsx`

---

## 🟡 ORTA ÖNCELİKLİ SORUNLAR

### **5. Realtime Subscriptions - Multiple Channels**

**Sorun**: Her context kendi realtime channel'ını açıyor. Çok fazla channel açılması performans sorununa yol açabilir.

**Etki**: Yavaşlama, bellek kullanımı artışı.

**Çözüm**: Channel'ları birleştir veya cleanup'ları doğrula.

**Dosyalar**: Tüm Context dosyaları

---

### **6. Error Handling - User Feedback Eksik**

**Sorun**: Bazı hata durumlarında kullanıcıya bilgi verilmiyor.

**Etki**: Kullanıcı ne olduğunu anlamaz.

**Çözüm**: Tüm try-catch bloklarında showAlert kullan.

**Dosyalar**: Tüm Context ve Screen dosyaları

---

### **7. Loading States - Eksik Gösterimler**

**Sorun**: Bazı ekranlarda loading state gösterilmiyor.

**Etki**: Kullanıcı işlem yapılıp yapılmadığını anlamaz.

**Çözüm**: Loading spinner'ları ekle.

**Dosyalar**: ServiceRequestForm, CreateQuoteForm

---

## 🟢 DÜŞÜK ÖNCELİKLİ SORUNLAR

### **8. Pagination Eksik**

**Sorun**: Tüm listeler (quotes, messages, appointments) pagination olmadan çekiliyor.

**Etki**: Çok fazla veri olduğunda yavaşlama.

**Çözüm**: Supabase pagination ekle (limit, offset).

**Dosyalar**: Tüm Context dosyaları

---

### **9. Optimistic Updates Yok**

**Sorun**: Kullanıcı bir işlem yaptığında (mesaj gönderme, teklif kabul) sunucudan yanıt bekliyor.

**Etki**: Yavaş hissedilen UX.

**Çözüm**: Optimistic updates ekle.

**Dosyalar**: MessageContext, QuoteContext

---

### **10. Image Upload Eksik**

**Sorun**: Fotoğraf yükleme özelliği yok.

**Etki**: Kullanıcılar araç/parça fotoğrafı ekleyemez.

**Çözüm**: Supabase Storage entegrasyonu.

**Dosyalar**: ServiceRequestForm, CreateQuoteForm

---

## 📋 ÖNCELİK SIRASI

### **Şimdi Düzeltilmesi Gerekenler** (Kritik)
1. ✅ MessageContext - Seller profil bilgisi
2. ✅ AppointmentContext - Vehicle join
3. ✅ ServiceRequestCard - Navigation
4. ✅ QuoteCard - Seller ID

### **Kısa Vadede** (Orta)
5. ⏳ Realtime cleanup
6. ⏳ Error handling
7. ⏳ Loading states

### **Uzun Vadede** (Düşük)
8. ⏳ Pagination
9. ⏳ Optimistic updates
10. ⏳ Image upload

---

## 🔧 DÜZELTME PLANI

**Sıra**:
1. MessageContext düzelt
2. AppointmentContext kontrol et
3. ServiceRequestCard rotasını düzelt
4. QuoteCard seller_id kontrol et
5. Test et
6. PayTR entegrasyonuna geç

---

**Son Güncelleme**: 25 Ocak 2026, 00:15  
**Durum**: Düzeltme Başlıyor

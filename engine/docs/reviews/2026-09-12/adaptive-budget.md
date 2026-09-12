# URL ve parametreye göre tarama bütçesi

2026-09-12. Lab kurulumu gerektirmeyen yerel testlerle uygulandı.

## Düzeltilen davranış

Önceki incelemede `RunModuleFromDB` akışında iki güvenli URL'nin XSS havuzunu tüketip üçüncü açıklı URL'yi testsiz bıraktığı doğrulanmıştı. Sınırsız mod artık hedef sayısı × 20/24 tahminleriyle kesilmiyor. Normal SQL taramasında, ilk birkaç deneme sonuç vermedi diye sonraki klasik payload'ları atlayan optimizasyon da kaldırıldı; yalnızca açıkça seçilen hızlı profilde korunuyor.

## Yeni dağıtım

- Varsayılan: modüllerde istek kotası yok. Keşfedilen ve kapsam içindeki yüzeyler çalıştırılır; mevcut keşif, profil, doğrulama ve süre ayarları geçerlidir.
- Pozitif `request_budget`: keşifte harcanan gerçek istekler çıkarılır; sıfır kalan pay sınırsız olarak yorumlanmaz. Global transport sınırı keşif, tekrar, yönlendirme ve harici protokol rezervasyonlarını kapsamaya devam eder.
- `requests_per_target`: pozitif global sınır yoksa keşif sonrasında URL/metot sayısından modül bütçesi hesaplanır. Query değerleri ve parametre sayısı URL sayısını şişirmez. Envantere yeni URL eklenirse türetilmiş bütçe büyür; açık global sınır büyütülmez.
- Sınırlı modül bütçesi, etkin modüllerin tahmini iş yüküne göre bölünür. Her modülün payı önce URL'lere eşit ayrılır, sonra o URL'nin parametre/yüzeyleri arasında bölünür. Payload sayısı tahminlere katılır.
- Ayrılmış pay başka bir hedef tarafından tüketilemez. Tamamlanan hedeflerin kullanmadığı istekler aynı modülün sonraki işlerine, modülün kullanmadığı pay ise sonraki modüllere aktarılır. Rezervasyonlar kilit altında yapılır; paralel işçiler kotayı birlikte aşamaz.
- Gerçek HTTP istemcisinde tahsilat transport seviyesindedir: retry/redirect hop'ları da sayılır. Diğer istemcilerde `Do` sınırında sayılır; gerçek istemci çift ücretlendirilmez. Kota hatası ağ hatası gibi yeniden denenmez.

## Kapsamın raporlanması

Hedef ortasında kota dolması `incomplete` sayılır; `targets_budget_exhausted` artar ve hedef `targets_tested` içine girmez. Yüzdenin paydası modüle uygun kapsam içi hedeflerdir. Gecikmeli timing doğrulaması tamamlanmadan sonuç özeti üretilmez; iptal edilen doğrulamalar eksik olarak kalır.

`module_budget_planned`, `module_target_finished`, `vuln_module_finished` olayları tarama geçmişine kaydedilir. Bütçe ve iptal kaynaklı `coverage_gap` mesajları verbose olmadan da terminalde görünür.

## Doğrulama

Yerel testler aşağıdaki davranışları doğruladı:

- SQLite envanterinden normal üretim loader'ı ile iki güvenli hedefin ardından açıklı üçüncü endpoint'e ulaşılması ve XSS bulgusunun üretilmesi.
- 120 toplam istek sınırında, bir ve sekiz işçiyle sonraki açıklı URL'nin korunması; sınırın aşılmaması ve yarım kalan hedeflerin %100 tamamlandı görünmemesi.
- XSS ve SQL için hedef ortasında 10 istekle kesilmenin açıkça eksik raporlanması.
- Aynı URL'nin birden fazla parametresinin bütçeyi çoğaltmaması ve boş endpoint kaydının enjeksiyon kotası almaması.
- XSS'ten sonraki SQL payının korunması; kullanılmayan modül ve hedef paylarının aktarılması.
- Açık global bütçede sıfır kalan payla hiçbir istek gönderilmemesi.
- Gerçek HTTP istemcisinde çift sayım olmaması; redirect ve paralel HTTP/harici rezervasyonların aynı sınıra uyması.
- Normal SQL profilinin geç sıradaki payload'lara ulaşması; hızlı profilin scout davranışının korunması.
- İptal, negatif config ve sayısal taşma kontrolleri; normal CLI çıktısında kapsam uyarısı.

Tam proje kontrolleri:

```text
go test ./... -count=1 -timeout 5m   PASS
go vet ./...                       PASS
```

Çıktılar bu klasörde `adaptive-budget-go-test.log` ve `adaptive-budget-go-vet.log` dosyalarındadır. Go'nun varsayılan cache konumunda erişim hatası alındığı için testlerde geçici klasörde ayrı bir `GOCACHE` kullanıldı. Bu ortamda CGO kapalı ve C derleyicisi bulunmadığından race detector doğrulaması yapılmadı; paralel davranış işlevsel testlerle kontrol edildi.

## Sınırlar

Sabit bir istek/süre sınırı altında bütün kontrollerin tamamlanacağı veya bütün açıkların bulunacağı vaat edilmez. Bütçe tahminleri ihtiyaç tahminidir; eksiksizlik kanıtı değildir. Kullanılmayan pay ileriye aktarılır; daha önce kesilmiş hedef otomatik baştan taranmaz. Kapsam öncelikliyse varsayılan sınırsız mod kullanılmalıdır.

Yeni dağıtım uygulamanın normal ardışık modül akışına bağlıdır. Eski grup API'leri ve lab'ın sınırlı entegrasyon yardımcı yolu aynı yeni dağıtıcıya geçirilmedi; normal üretim akışı doğrudan regresyon testine alındı. Harici lab koşusu yeniden çalıştırılmadı.

İnceleme öncesinden kalan loader/SQL değişiklikleri korundu. Çalışma alanının kökündeki `akca.exe` güncel kaynak koddan yeniden derlendi.

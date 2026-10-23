# Crawler ve parametre motoru düzeltmeleri

20 Ekim 2026 tarihli incelemedeki CP01–CP11 bulgularının uygulama özeti:

- CP01: GET form şablonu zayıf link kaydına tercih ediliyor. Form alanlarının bulunduğu URL hem keşif kimliği hem gönderim URL'si olarak korunuyor. POST action'ından şablonsuz GET üretilmiyor.
- CP02: Duplicate kontrolü yeniden ziyaret etmeyi önlüyor; sonradan yakalanan body/header şablonunun ve runtime gözleminin kaydedilmesini önlemiyor. Bunun için ek POST gönderilmiyor.
- CP03: JSON mutasyonu ortak replay katmanını kullanıyor. Büyük sayılar ve diziler korunuyor; null veya uyumsuz kök/path durumları farklı bir gövdeye dönüştürülmüyor.
- CP04: Multipart boundary'nin harf büyüklüğü korunuyor. Dosyalar ve diğer partlar taşınıyor; bozuk gövdeden minimal istek üretilmiyor. Keşif gerektiğinde mevcut partları koruyarak yeni alan ekleyebiliyor.
- CP05: XML, multipart ve raw GraphQL form-urlencoded olarak çıkarılmıyor. XML mevcut leaf/path veya attribute üzerinden değiştirilir. Raw GraphQL'de güvenle değiştirilebilen scalar literal/default alanları kullanılır; ayrı variables gövdesi olmayan, defaultsuz değişkenler için yeni bir istek formatı uydurulmaz.
- CP06: Query, POST JSON ve native body sinyalleri ancak başarılı bağımsız replay ile doğrulanır. Replay hatası veya bütçe yetersizliği doğrulanmış parametre oluşturmaz.
- CP07: Aktif probe girişimleri atomik olarak bütçeden ayrılır. Başarısız gönderimler, prefilter, replay ve tip denemeleri aynı endpoint bütçesini kullanır. Mevcut baseline/kalibrasyon istekleri bu aktif bütçeden ayrıdır.
- CP08: Query, template ve differential parametre yazım hataları çağırana döner. Bazı endpointler başarılı olsa bile veri kaybı faz başarısı sayılmaz. Transfer yolundaki yazım hataları da döndürülür.
- CP09: Sondaki slash, escaped path ve aynı query anahtarının değer sırası korunur.
- CP10: Attribute varlığı ile boş attribute değeri ayrıdır. Açık boş değerler korunur; select varsayılanları ve disabled seçenekler dikkate alınır.
- CP11: Endpoint aileleri path/query/body adlarında büyük-küçük harf ayrımını korur. Host/scheme normalizasyonu ve ID tabanlı aileleme devam eder.

Kalıcı regresyon testleri:

- `engine/internal/crawler/request_integrity_test.go`
- `engine/internal/params/request_integrity_test.go`

Doğrulama: Tüm Go test paketi ve `go vet ./...` geçti. Ağ gerektiren entegrasyon testleri yalnızca yerel test sunucularıyla çalıştırıldı; canlı hedef taraması yapılmadı.

# Çekirdek inceleme düzeltmeleri

20 Ekim 2026. Kapsam: önceki incelemedeki E01–E10 ve R01–R16.

## Request bütünlüğü

- E01: JSON container/bozuk JSON, bulunamayan GraphQL/XML alanı ve bozuk multipart mutasyonu açık hata döndürür. Başka yüzeye veya minimal requeste fallback yapılmaz; başarısız mutasyon ağa gönderilmez. Boş XML leaf alanları desteklenir.
- E03: JSON requestleri `UseNumber` ile çözümlenir; hedef dışı büyük sayılar korunur.
- E04: Path mutasyonu escaped segmentler üzerinden yapılır; sibling encoding ve trailing slash korunur.
- E07: GraphQL scalar değeri literal splice ile değiştirilir; `$` replacement ifadesi olarak yorumlanmaz. Escaped string, sayı exponenti ve string/comment içindeki sahte eşleşmeler korunur.
- R04–R05: Parametresiz, native ve header-only probe yolları body/header şablonunu korur. Endpoint loader da şablonu parametresiz hedefe aktarır.
- R07: JWT baseline, geçersiz imza, tamper ve replay kontrolleri yakalanan header/cookie/query taşıyıcısını değiştirir; query içindeki tekrarlı değerlerin doğru occurrence'ı korunur.
- R10–R11: JWT claim sayıları kayıpsız çözülür; `null`/object olmayan claims mutation worker'ını panic'e sokmaz.

## Oturum ve yürütme

- R01: Header override case-insensitive ve deterministiktir. Seçilen auth profili, yakalanmış requestin eski auth headerlarını devralmaz.
- R02: 520–527 retry dalı unsafe methodları tekrarlamaz; son yanıt body’si kapatılıp kaybedilmez.
- R08–R09: Açık User-Agent korunur; session cookie'leri açık cookie mutasyonunu aynı isimle tekrar eklemez.
- R03: Analyzer, generator ve reflection fazı context iptalini taşır; iptal edilmiş faz başarı checkpoint'ine yazılmaz.
- R06: Payload kayıt anahtarı scan + native method + URL + parameter + location içerir. Reflection delivery methodu ile native method ayrı taşınır. Aktif loader eski global `URL::parameter` kayıtlarına fallback yapmaz; eski kayıtlar silinmez.
- R16: `endpoints_tested`, en az bir modül hedefi tamamlanan ayrı method/URL çiftlerini sayar. Faz yüzdesinden sayı üretilmez. Bu sayaç, bütün modüllerin o endpointte tamamlandığı anlamına gelmez.

## Encoding ve payload seçimi

- E02: Offensive semantic kimliği normalize edildikten sonra control bağlantısı kurulur; dedupe farklı `ControlFor` bağlantılarını birleştirmez. Seçim orphan kontrol eklemez veya kontrolü bulunmayan WAF varyantını seçmez.
- E05: JSON Unicode wire encoding, semantic `Payload.Value` değerinden `WireEncoding` metadata'sıyla ayrılır. Sadece enjekte edilen string serialization sırasında kaçışlanır; literal backslash dizileri otomatik decode edilmez.
- E06: Multipart ek URL-encoding katmanı sayılmaz; form/body/post aliasları form katmanını hesaba katar.
- E08: SQL comment/case dönüşümü quoted veri/identifier, dollar-quoted veri ve mevcut yorumları korur; yalnızca dışarıdaki keyword/separatorları değiştirir. Belirsiz/unclosed quoted fragmanlar konservatif olarak korunur.
- E09: Gerçek transport davranışı üretmeyen chunked/folding/jitter/fragmentation iddiaları ve inert marker headerları kaldırıldı. Bunlar yeni bir transport özelliği olarak uygulanmadı. Eski strateji ID'leri öğrenme uyumluluğu için tutuldu; isim/açıklamaları gerçek davranışı belirtir.
- E10: Wire dedupe case ve whitespace dahil payload byte değerini korur.

## Kanıt sınırı

- R12: Positive probe/replay rolleri aynı fiziksel exchange kimliğini iki bağımsız çalışma sayamaz. Exchange kimliği olmayan aynı request/response da attempt numarası değiştirilerek çoğaltılamaz. WebSocket/raw HTTP üreticileri gerçek exchange kimliğini taşır. H2 üreticisindeki tek exchange kopyası ikinci attempt olarak sunulmaz; replay eksikse final kanıt kabul edilmez.
- R13: Versioned observationlar candidate'ın scan, module, logical endpoint, parameter ve belirtilmiş location bağlamına bağlanır. Negative control/retrieval'ın gerçek request URL'si farklı olabilir; logical hedef aynı kalır. Browser-read kayıtları da hedef bağlamı ve ayrı read kimliği taşır.
- R14: `RequiresStateProof` proof-type dalından önce uygulanır. Upload kanıtına gerçek before observationı da eklenmiştir.
- R15: Confidence `Suppressed` ise suppression bayrağı da true, score sıfırdır.

## Diğer inceleme notları

- Sahte imzalı, gelecekte exp taşıyan `jwt_expired_admin`, ölçtüğü davranışı belirten `jwt_fabricated_admin_claims` olarak etiketlendi; expiration kanıtı sayılmaz.
- Açık payload bütçesi 10/15'e sessizce düşürülmez; global request budget ve rate limit korumaları devam eder.
- WAF öğrenme kaydının teknik, decoder, blocked/allowed karakter alanları birlikte aktarılır.
- `targets_blocked`, mevcut skipped toplamını bozmadan ayrı alt sayaç olarak yayımlanır.
- Sequential modül fazı hedefleri bir kez yükleyip planlar; snapshot yalnızca o invocation boyunca yaşar. Resume/yeni invocation yeniden yükler. Ölçülmüş bir hızlanma iddiası yoktur.

## Doğrulama

Kalıcı regresyon testleri reflection, httpclient, modules, mutation, payloadgen, storage, verification ve app paketlerine eklendi; WAF protokol iddiaları ayrıca test ediliyor.

- `go test ./... -count=1`: son tam koşuda bütün paketler geçti.
- `go vet ./...`: geçti.
- `git diff --check`: geçti.
- İlk tam koşuda scheduler testinde Windows geçici SQLite dosyası cleanup kilidi görüldü. İlgili paket `-count=3` ile ve sonraki tam koşuda geçti; scheduler kaynakları değiştirilmedi.
- Ağ kullanan entegrasyon testleri, sandbox localhost bağlantılarını engellediği için izinli ortamda çalıştırıldı. Canlı hedef kullanılmadı.

Bu çalışma yerel unit/integration testleriyle doğrulanır; canlı hedef/WAF taraması veya genel güvenlik sertifikası değildir.

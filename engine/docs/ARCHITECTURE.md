# AKCA Advanced Web Security Scanner Architecture

Bu belge motorun çalışma sınırlarını, tarama veri akışını ve bir güvenlik
bulgusunun hangi kanıtlarla raporlanabileceğini tanımlar. Kod ile çelişmesi
durumunda `internal/app`, `internal/modules`, `internal/verification` ve
`internal/config` altındaki uygulama esas alınır.

False-positive azaltma ve modül kanıt sınıfları için tamamlayıcı not:
`docs/FALSE_POSITIVE_AUDIT.md`.

## 1. Çalıştırma yüzeyleri

- `cmd/akca`: CLI, benchmark ve rapor dışa aktarma yüzeyi.
- `cmd/akca-api`: API süreci.
- `cmd/akca-policy`: politika doğrulama aracı.
- `internal/app`: tarama yaşam döngüsü, faz orkestrasyonu, checkpoint/resume ve
  sonuçlandırma.
- `internal/config`: tüm çalışma, kapsam, kimlik ve kanıt sözleşmelerinin tek
  doğrulama sınırı.

## 2. Tarama veri akışı

Motor aşağıdaki sırayı izler:

1. Bootstrap ve kaynak limitleri
2. Hedef/kimlik doğrulama preflight kontrolü ve ilk yanıt `502` ise hızlı sonlandırma
3. Teknoloji/WAF parmak izi ve isteğe bağlı WAF kalibrasyonu
4. OpenAPI, RAML, Postman, HAR, WSDL, GraphQL, protobuf ve AsyncAPI içe aktarımı
5. Kapsam kontrollü ve oturum korumalı crawl
6. Runtime sensor keşfi
7. JavaScript analizi ve bulunan URL'lerin yeniden crawl edilmesi
8. Sözleşme ile çalışma zamanı arasındaki shadow API karşılaştırması
9. Parametre keşfi
10. Exposure fuzzing ve 403 bypass kuyruğu
11. Reflection analizi ve bağlama uygun payload üretimi
12. Sıralı güvenlik modülleri
13. OAST drain, korelasyon ve raporlama

Her faz olay üretir, başarı/başarısızlık durumunu checkpoint'e yazar ve iptal
sinyalini taşır. Kısmi faz hataları taramayı `partial`; iptal ve zaman aşımı ise
ayrı nihai durumlarla sonlandırır.

## 3. Ana katmanlar

| Katman | Sorumluluk | Güvenlik sınırı |
| --- | --- | --- |
| Scope + HTTP | URL kapsamı, redirect, hız, eşzamanlılık, bütçe, oturum izolasyonu | Kapsam dışına istek yok; rol istekleri ortak oturumu değiştirmez |
| Discovery | Crawl, JS, API sözleşmesi, parametre ve teknoloji keşfi | Keşif verisi doğrudan zafiyet sayılmaz |
| Planning | Endpoint/risk etiketi/modül eşleme ve payload bütçesi | Devre dışı sınıf veya pasif mod aktif teste dönüşmez |
| Modules | Sınıfa özgü probe ve kanıt toplama | Her bulgu tiplenmiş sinyal üretmek zorunda |
| Verification | Negatif kontrol, replay, identity/state/OAST/DOM kanıt politikası | Politika karşılanmazsa aday bastırılır |
| Safe mutation | Yazma öncesi snapshot, tekil kaynak kilidi ve cleanup sonucu | Cleanup başarısızsa bulgu yayınlanmaz ve hata olayı oluşur |
| Storage/report | SQLite, kanıt, checkpoint, rapor ve karşılaştırma | Saklanan yapılandırma ve kimlik bilgileri redakte edilir |

## 4. Modül ve kanıt modeli

Modül kataloğu `internal/modules/manifest_*.go`, yürütme eşlemesi
`internal/modules/module_runner.go`, sıra ise `internal/app/vulnmodules.go`
tarafından yönetilir. Yeni bir modül bu üç yerde ve
`internal/verification/proof_policy.go` içinde eksiksiz tanımlanmalıdır.

Başlıca kanıt sınıfları:

- Configuration/content: pasif ve kesin yapılandırma işaretleri.
- Differential replay: native baseline, negatif kontrol ve bağımsız tekrarlar.
- Identity boundary: kaynak sahibi, yabancı rol ve anonim kontrol.
- State mutation: yazma öncesi/sonrası bağımsız state okuması ve doğrulanmış
  cleanup.
- OAST/runtime/DOM: tarama ve payload kimliğiyle korele harici çalışma kanıtı.
- Protocol/schema: protokol ayrışması veya doğrulanmış şema görünürlüğü.

HTTP 2xx tek başına güvenlik etkisi değildir. Yanıt farkı da kaynak sahipliği,
yetki ihlali veya kalıcı durum değişimini kanıtlamaz.

Yanlış pozitif azaltma bir sansür veya modül kapatma mekanizması değildir:
modüller kapsam içindeki keşfedilmiş yüzeylerde probe göndermeye devam eder,
ancak bulgu yayınlama eşiği sınıfa özgü kanıt politikasına bağlanır. Keşfedilen
GET yüzeyinden sentetik POST form kanıtı üretilmez; gerçek POST/PUT/PATCH
endpoint'leri kendi kayıtlı yöntemiyle ayrıca taranır.

Kanıt sözleşmesi eksik olan stateful kontroller sessizce kaybolmaz. Motor
`coverage_gap`/coverage-probe olaylarıyla hangi endpoint, yöntem ve modül için
ek policy gerektiğini saklar. HPP ve IDOR gibi read-only GET yüzeylerinde sınırlı
coverage probe yapılabilir; bu sinyaller proof tamamlanmadan zafiyet bulgusuna
dönüşmez.

React Server Components RCE kontrolü RSC payload'larını aktif olarak dener, fakat
HTTP 500/digest yanıtını tek başına RCE saymaz. RCE bulgusu için runtime
sensor'den tarama kimliğiyle korele `deserialization` sink kanıtı gerekir.

## 5. Durum değiştiren modüller

Aşağıdaki kontroller uygulamaya özgü kayıtlı sözleşme olmadan çalışmaz:

- Account recovery: `account_recovery_proof_policies`
- Webhook security: `webhook_proof_policies`
- CSRF: `csrf_proof_policies`
- Session lifecycle: `session_lifecycle_proof_policies`; kimlik bilgisi ayrıca
  `disposable_credential` olarak işaretlenmelidir.
- Business logic: `business_logic_proof_policies`
- Race condition ve synchronized race: `race_proof_policies`
- HPP: `hpp_proof_policies`
- BFLA: `authorization_policies`
- BOLA/IDOR ve tenant isolation: `object_authorization_policies`
- File upload: yazmadan önce tamamen çözülebilen `file_upload_proof_policies`.

Stateful sözleşmeler eylem, negatif kontrol, salt-okunur state isteği ve cleanup
isteğini taşır. Tüm URL'ler kapsam içinde olmalı; action/cleanup yazma, state ise
GET/HEAD olmalıdır. İstek gövdeleri ve özel başlıklar rapora kaydedilirken
tamamen maskelenir.

## 6. Pasif mod değişmezi

`PassiveMode` yalnızca profil adı değildir. Profil normalizasyonundan sonra da
fuzzing, WAF kalibrasyonu, 403 bypass, OAST, headless browser, business logic,
race, second-order, parametre keşfi ve reflection kapalı tutulur. Pasif modül
listesi yalnızca önceden alınmış yanıtlar ve güvenli metadata/TLS kontrollerinden
oluşur. Secret ve sensitive-data modülleri pasif modda marker enjekte etmez.

## 7. Genişletme kontrol listesi

Yeni veya değişen modül için:

1. Manifest, dispatcher, yürütme sırası ve proof policy birlikte güncellenir.
2. Native baseline ile sınıfa özgü tiplenmiş sinyal ayrılır.
3. En az bir negatif kontrol ve gerekli bağımsız tekrar eklenir.
4. Rol kanıtında rastgele ID yerine bildirilmiş sahiplik sözleşmesi kullanılır.
5. Yazma varsa state snapshot ve yazmadan önce çözülebilir cleanup zorunludur.
6. Pasif modda ağ mutasyonu yapılmadığı test edilir.
7. Hassas request body/header değerlerinin storage redaksiyonu test edilir.
8. Pozitif, güvenli-negatif, kararsız yanıt ve cleanup-hata yolu test edilir.
9. `go test ./...`, `go vet ./...` ve kritik eşzamanlı paketlerde race testi
   geçmeden değişiklik tamamlanmış sayılmaz.

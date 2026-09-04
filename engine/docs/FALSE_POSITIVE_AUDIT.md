# False Positive Audit

Bu not, modülleri kapatmadan false-positive oranını azaltmak için kullanılan
kanıt modelini ve gözden geçirilen risk alanlarını özetler. Esas kaynak kod
`internal/modules`, `internal/verification` ve `internal/app/vulnmodules.go`
altındadır.

## Prensip

- Kullanıcının veya keşif motorunun bulduğu yüzey baştan sansürlenmez.
- Probe kabiliyeti korunur; bulgu yayınlama ise modülün kendi kanıt tipine
  bağlanır.
- Tek yanıt, tek status değişimi veya payload echo'su exploit kanıtı sayılmaz.
- State-changing kontrollerde cleanup/state policy yoksa mutasyon yapılmaz;
  bunun yerine `coverage_gap` olayı üretilir.
- Read-only coverage mümkünse çalışır ve “ek kanıt gerekiyor” bilgisi saklanır.

## Kanıt sınıfları

- Passive/configuration: `security_headers`, `cookie_security`, `tls_misconfig`,
  `sensitive_data`, `secret_exposure`, `script_source`, `vulnerable_components`.
- Exposure/fingerprint: `actuator`, `framework_debug`, `swagger_exposure`,
  `sensitive_file_discovery`, `cloud_native_exposure`, `devops_exposure`,
  `firebase_misconfig`, `spring_cloud_jolokia`, `saas_exposure`, `grpc_scan`.
- Replay/header differential: `cors`, `open_redirect`, `host_header`,
  `host_poisoning`, `crlf`, `cache_poisoning`, `cache_deception`,
  `route_auth_bypass`, `proxy_path_confusion`, `nextjs_bypass`, `cpdos`.
- Runtime/OAST/DOM: `blind_xss`, `ssrf`, `xxe`, `command_injection`,
  `server_side_js_injection`, `pdf_injection`, `react_rsc_rce`, `client_ssti`.
- Identity/state proof: `idor`, `tenant_isolation`, `bfla`, `mass_assignment`,
  `business_logic`, `race_condition`, `race_condition_sync`, `account_recovery`,
  `webhook_security`, `csrf`, `session_lifecycle`, `hpp`, `file_upload`.
- Parser/protocol/schema: `parser_differential`, `http_smuggling`, `smuggling`,
  `graphql`, `websocket`, `ldap`, `xpath`, `ldap_xpath_injection`, `nosql`,
  `sqli`, `ssti`, `lfi`, `insecure_deserialization`, `llm_injection`.

## Bu turda sıkılaştırılan alanlar

- Header target/proof kısıtları kaldırıldı. Header yüzeyleri artık genel
  severity filtresine takılmıyor; header payload güvenliği modül seviyesinde
  korunuyor.
- `api_exposure` HTML shell veya normal sayfadaki token/internal_id metnini API
  data exposure saymıyor; JSON/structured API yüzeyi veya açık API route gerekir.
- `server_side_js_injection` merkezi guard'ı artık sadece SSJS marker'larını ve
  zaman sinyalini kabul ediyor; generic 200 body kabul edilmiyor.
- `csti_detection` literal payload echo'sunu veya baseline'da zaten bulunan
  eval token'ını kabul etmiyor.
- `framework_debug`, `actuator`, `spring_cloud_jolokia`, `saas_exposure`,
  `pdf_injection`, `swagger_exposure`, `sensitive_file_discovery`,
  `cloud_native_exposure` ve `grpc_scan` merkezi guard'ları kendi fingerprint
  koşullarıyla hizalandı.
- `backup_archives`, `cloud_takeover` ve `devops_exposure` merkezi guard'ları
  artık sadece modülün özgül magic-byte/provider/schema parmak izleriyle
  doğrulanıyor.
- `file_upload`, `http_smuggling`, `nextjs_bypass`, `iis_discovery` ve GraphQL
  type-inversion sinyallerinde genel “dolu yanıt” kabulü kaldırıldı; marker,
  canary, auth status değişimi, source marker veya yeni hassas veri/hata
  koşulları aranıyor.
- `cloud_native_exposure` Kubernetes PodList kontrolündeki status öncelik hatası
  düzeltildi.
- `proxy_path_confusion` tek seferlik 200 yerine bypass yanıtını yeniden oynatıp
  aynı kaynak fingerprint'ini arıyor.
- `HPP`, `IDOR/BOLA` ve stateful proof modülleri policy eksikliğinde sessiz
  düşmüyor; coverage/proof-gap olayı bırakıyor.
- `secret_exposure` artık aktif marker veya replay isteği göndermeden pasif
  response kanıtı üzerinden çalışıyor; aynı response body için secret detector
  sonuçları cache'leniyor.
- `crlf` parametre adına göre elenmiyor; false-positive kontrolü token'lı header
  veya body response-splitting kanıtında yapılıyor.
- `http_smuggling` ve `smuggling` tarafında aynı route/origin için gereksiz
  tekrarlar azaltıldı; HTTP/1.1 control ve HTTP/2 ALPN sonuçları yeniden
  kullanılıyor.
- Crawler linked API/service subdomainlerini varsayılan scope'a otomatik
  eklemiyor; bu geniş kapsam artık explicit opt-in davranışıdır.

## Korunan sınırlar

Bu sınırlar özellik kapatma değildir; gerçek hedefi bozmamak ve raporun exploit
kanıtını doğru sınıfta tutmak için korunur:

- Scope dışına istek yok.
- Passive mode aktif mutasyona dönmez.
- Cleanup/state policy olmadan yazma odaklı proof yapılmaz.
- OAST, runtime sensor veya browser yoksa ilgili dış kanıt bulgusu basılmaz;
  mümkünse coverage olayı üretilir.

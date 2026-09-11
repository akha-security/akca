# AKCA kod ve bulgu kalitesi incelemesi — 9 Eylül 2026

İncelenen commit: `1e5626f` (v0.1.8). İnceleme başlangıcında çalışma ağacı temizdi.

## Sonuç ve kapsam

AKCA'da merkezi doğrulama, negatif kontrol, kimlik/state sözleşmeleri, OAST, checkpoint ve CI kalite kontrolleri mevcut. En yüksek getirili geliştirme, modüllerin güvenlik etkisini gerçekten kanıtlamasını ve kapsama metriklerinin gerçekte yapılan işi göstermesini sağlamak.

13 yerel yeniden üretim testi çalıştırıldı. Bunlar **mevcut sorunlu davranışı göstermeyi amaçlayan testlerdir**; PASS sonucu hatanın düzeltildiği anlamına gelmez. Beş modülde güvenli örneklerden bulgu üretildi; üç doğrulama yolunda açık/çalışma sinyali kaçırıldı; beş yardımcı mantık/metrik sorunu gösterildi.

Testler kontrollü HTTPDoer/browser fixture'ları ve gerçek modül/doğrulama koduyla çalıştı. Üçüncü taraf sistemlerde aktif tarama yapılmadı. Bu değerlendirme saha false-positive yüzdesi ölçümü veya tüm modüllerin eksiksiz sertifikasyonu değildir. Özellikle browser ve ham TCP senaryolarında fixture sınırı aşağıda belirtilmiştir.

Kullanıcının tercihi doğrultusunda ham kanıtlar korunur; maskeleme geliştirme önerisi değildir.

## Öncelik tanımı

- **P1:** Tarama sonucuna güveni doğrudan bozan yanlış bulgu, gerçek açık kaçırma veya yanlış yeniden test kararı.
- **P2:** Ölçüm, benzerlik, doğrulama desteği ve sürdürülebilirlik sorunları.

Buradaki P1/P2 düzeltme önceliğidir. Modülün ürettiği High/Critical etiketi ise testte gözlenen çıktı olup bu incelemenin risk puanı değildir.

## False-positive olarak yeniden üretilen modüller

### 1. P1 — route_auth_bypass: olmayan rota + farklı herkese açık sayfa Critical oluyor

**Test:** `TestAuditOrdinaryRouteProducesCriticalBypass`

Normal rota 404, noktalı virgülle değiştirilen alternatif rota herkese açık bir dokümantasyon sayfası döndürdü. Sonuç: **Critical / HighConfidence**.

404 tek başına korumalı kaynağı kanıtlamıyor. Başarılı yanıt kontrolü 200/206, 32 karakterden uzun içerik ve bazı hata/login metinlerinin yokluğuyla yetiniyor. Yetkili kullanıcının eriştiği kaynakla eşleşme aranmıyor. URL'de `admin` bulunması severity'yi Critical'a çıkarıyor.

**Düzeltme:** Yetkili referans yanıtı veya tanımlı kaynak/izin sözleşmesiyle aynı özel kaynağa erişimi kanıtla. Kaynak eşleşmesi yoksa rota davranışını keşif kaydı olarak sakla. Severity'yi URL kelimesine değil doğrulanan etkiye bağla.

**Kod:** [modules/route_auth_bypass.go:63](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/modules/route_auth_bypass.go:63>), [modules/route_auth_bypass.go:165](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/modules/route_auth_bypass.go:165>), [modules/route_auth_bypass.go:154](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/modules/route_auth_bypass.go:154>).

### 2. P1 — llm_injection: sistem talimatını açıklamayı reddeden yanıt sızıntı sayılıyor

**Test:** `TestAuditLLMRefusalProducesLeakFinding`

Yanıt: `I cannot disclose my system prompt: those instructions are private.`

Sonuç: **High / HighConfidence — LLM System Prompt Extraction / Disclosure**.

`system prompt:` ifadesinin baseline'da bulunmaması yeterli görülebiliyor. Modelin ret cevabı ve gerçekten sızan içerik ayrılmıyor. Diğer dallarda talep edilen sabit metni üretmek de tek başına instruction override kanıtı sayılabiliyor; uygulamanın gerçek kuralı bilinmeden ihlal çıkarımı yapılamaz.

**Düzeltme:** Kullanıcının tanımladığı yasak işlem/korunan bilgi için test sözleşmesi kullan. Güvenli ret, sıradan metin üretimi ve gerçek sınır ihlalini ayrı sonuçlandır. Kontrollü lab'da gizli, test sorgusunda bulunmayan canary kullan; gerçek hedefte doğrulanamayan çıktıyı aday olarak tut.

**Kod:** [modules/llm_injection.go:174](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/modules/llm_injection.go:174>), [modules/llm_injection.go:196](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/modules/llm_injection.go:196>), [modules/llm_injection.go:216](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/modules/llm_injection.go:216>).

### 3. P1 — ws_cswsh: herhangi bir custom header kimlik bilgisi sayılıyor

**Test:** `TestAuditPublicWSWithCustomHeaderProducesHighFinding`

Herkese açık bir WebSocket fixture'ı ve yalnızca `Accept-Language: tr` custom header'ı kullanıldı.

Sonuç: **High / HighConfidence — CSWSH with Ambient Credentials**.

`hasAuth`, custom header veya request-template header haritasının boş olmamasını kimlik kanıtı kabul ediyor. 101 yanıtından sonra özel veri okunması veya yetkili eylem gösterilmiyor.

**Düzeltme:** Gerçekte gönderilen cookie/kimlik profili, anonim karşılaştırma ve WebSocket mesaj düzeyinde özel kaynak erişimi gerekir. Browser'ın bu kimlik bilgisini çapraz site istekte gerçekten taşıyabildiği ayrıca gösterilmeli.

**Sınır:** Bu test gerçek browser handshake'i değil, modülün 101 yanıtını ve header yapılandırmasını nasıl sınıflandırdığını doğrular.

**Kod:** [modules/ws_cswsh.go:46](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/modules/ws_cswsh.go:46>), [modules/ws_cswsh.go:52](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/modules/ws_cswsh.go:52>).

### 4. P1 — jsonp_callback: normal JSONP özelliği ve public user_id High oluyor

**Test:** `TestAuditPublicJSONPProducesHighFinding`

Kimliksiz herkese açık blog yazarı bilgisi, normal callback sarmalayıcısıyla döndü. Sonuç: **High / HighConfidence**.

Callback adını kabul etmek JSONP'nin normal davranışı. `user_id`, `email` veya `token` kelimesi görmek verinin özel olduğunu göstermiyor.

**Düzeltme:** JSONP keşfini envanter bilgisi olarak sakla. Güvenlik bulgusu için kimliğe özgü özel verinin browser üzerinden başka origin tarafından okunmasını veya callback sözdizimi kırılarak gerçek kod çalışmasını kanıtla.

**Kod:** [modules/jsonp_callback.go:45](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/modules/jsonp_callback.go:45>), [modules/jsonp_callback.go:56](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/modules/jsonp_callback.go:56>).

### 5. P2 — parser_differential: normal ayrıştırma davranışından güvenlik ihlali çıkarılıyor

**Test:** `TestAuditOrdinaryJSONParserProducesFinding`

Body gönderilmediğinde “no input”, body gönderildiğinde “request received and parsed normally” yanıtı veren güvenli fixture kullanıldı. Gateway, yetki geçişi veya state değişikliği yoktu. Sonuç: **Medium / HighConfidence**.

Kod duplicate-key isteğinin 200 ve farklı body üretmesini kabul ediyor; tek anahtarlı user/admin kontrolleriyle iki parser arasında zıt yorum ispatlanmıyor.

**Düzeltme:** İlk-değer, son-değer ve tek-anahtar kontrolleri ekle; hangi iki katmanın farklı yorumladığını ve bunun hangi güvenlik kuralını ihlal ettiğini kanıtla. Yalnızca parser davranışı keşif kaydı olmalı.

**Kod:** [modules/parser_differential.go:57](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/modules/parser_differential.go:57>), [modules/parser_differential.go:68](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/modules/parser_differential.go:68>).

## Gerçek sinyali kaçıran yollar

### 6. P1 — cors: baseline aynı zamanda probe olarak kullanıldığı için açık bastırılıyor

**Test:** `TestAuditCORSReflectingHTTPOriginsMissed`

Fixture her HTTP(S) Origin değerini yansıtıyor, credentials'a izin veriyor, `null` origin'ini reddediyordu. Sonuç: **0 bulgu**.

`baseACAO == https://benign.example` dalında `handleProbeResult(..., baseline)` çağrılıyor. Merkezi guard probe ACAO ile baseline ACAO aynı olduğundan sinyali reddediyor. Ardından yalnızca null testi yapılıp çıkılıyor.

**Düzeltme:** Native/no-Origin baseline ile iki ayrı saldırgan origin'ini ayır. Null origin'in reddedilmesi arbitrary-origin açıklığını kapatmamalı. Replay/negatif kontrol istekleri de geçerli origin biçimini ve doğru referansı korumalı.

**Kod:** [modules/cors.go:107](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/modules/cors.go:107>), [modules/fp_guard.go:481](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/modules/fp_guard.go:481>).

### 7. P1 — second_order: kanıt gözlemleri geçersiz, çalıştırma sinyali de düşüyor

**Test:** `TestAuditSecondOrderExecutionSuppressed`

Kaydedilmiş çalıştırılabilir XSS payload'ı ve browser fixture'ından execution sinyali verilmesine rağmen bulgu bastırıldı.

Native baseline yalnızca sentetik response içeriyor; geçerli request bilgisi yok. Ayrıca `buildCandidate` tarafından eklenen positive-probe gözlemi mutate callback'inde aynı rol/attempt ile tekrar ekleniyor. Gözlem doğrulaması tekrarı reddediyor; native baseline zorunluluğu da karşılanmıyor.

**Düzeltme:** Yazmadan önce gerçek baseline/state kaydı, tekil observation kimlikleri ve korele DOM execution kanıtı kullan. DOM'da marker'ın görünmesi ile çalışması arasındaki mevcut karışıklığı da aynı düzeltmede gider.

**Sınır:** Browser execution sinyali kontrollü renderer ile verildi; gerçek browser exploit zinciri bu testte yürütülmedi.

**Kod:** [modules/secondorder.go:50](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/modules/secondorder.go:50>), [modules/secondorder.go:76](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/modules/secondorder.go:76>), [modules/secondorder.go:90](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/modules/secondorder.go:90>), [verification/observation.go:122](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/verification/observation.go:122>).

### 8. P1 — http_smuggling: ham TCP kanıtı sıradan HTTP isteğiyle tekrar doğrulanıyor

**Test:** `TestAuditSmugglingProofReplayedAsOrdinaryHTTP`

Modülün iki ham TCP doğrulamasından sonra oluşturduğu evidence şekli, gerçek `verifyAndBuild` yoluna verildi. Doğrulama iki sıradan POST gönderdi; attack body/canary bulunmadığından bulgu bastırıldı.

`smuggling` module-managed proof listesinde, `http_smuggling` ise değil. Üretilen request kaydı raw attack gövdesini taşımıyor. Protokol ayrışması sıradan HTTP replay ile yeniden üretilemez.

**Düzeltme:** Her iki protokol modülüne gerçek raw exchange + kontrol + bağımsız connection gözlemlerini taşıyan ortak proof sözleşmesi ver. Doğrulamada aynı protokol prober'ını kullan.

**Sınır:** Ham TCP üzerinden çalışan bir proxy exploit'i kurulmadı; doğrulanmış raw-protocol kanıtının merkezi doğrulamaya aktarımındaki kayıp gösterildi.

**Kod:** [modules/http_smuggling.go:234](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/modules/http_smuggling.go:234>), [modules/verification_probe.go:120](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/modules/verification_probe.go:120>), [modules/verification_probe.go:167](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/modules/verification_probe.go:167>).

## Sonuçların güvenilirliğini bozan destek mantıkları

### 9. P1 — finding replay yalnızca body hash'ine göre “still_vulnerable” kararı veriyor

**Test:** `TestAuditReplayHashIgnoresSecurityHeaders`

Aynı boş body'ye sahip dış yönlendirme ve düzeltilmiş iç yönlendirme, farklı Location başlıklarına rağmen aynı normalized hash üretti.

Replay akışı eşleşme için yalnızca bu hash'i kullanıyor; status/header farkını karar koşuluna katmıyor. Bu yüzden header tabanlı açıkların düzeltildiğini yanlış değerlendirebilir. CORS, redirect ve boş-body yetki cevapları özellikle etkilenir.

**Düzeltme:** Modül/sinyal türüne göre yeniden doğrulama yap: Location hedefi, ACAO/ACAC, status, kimlik sınırı, state etkisi veya timing/OAST kanıtı. Genel gövde hash'i yardımcı veri olarak kalmalı.

**Sınır:** Hash çakışması testle, bunun `still_vulnerable` kararına taşınması kod akışıyla doğrulandı; ReplayFinding'in tam DB/HTTP uçtan uca testi bu turda yazılmadı.

**Kod:** [verification/observation.go:72](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/verification/observation.go:72>), [app/finding_replay.go:169](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/app/finding_replay.go:169>), [app/finding_replay.go:195](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/app/finding_replay.go:195>).

### 10. P2 — bodiesSimilar içeriği karşılaştırmıyor

**Test:** `TestAuditSameLengthDifferentBodiesAreSimilar`

100 tane A ve 100 tane B karakteri **benzer** kabul edildi.

Fonksiyon eşitlik kontrolünden sonra yalnızca uzunluk farkının %8 altında olmasına bakıyor. Nginx alias, route bypass, Next.js, debug, sensitive files, Spring/Jolokia ve Swagger kontrolleri bunu kullanıyor. Gerçek farklı kaynaklar yanlışlıkla elenebilir; eşit uzunluklu kararsız yanıtlar kararlı kabul edilebilir.

**Düzeltme:** Mevcut volatile-field normalizasyonundan sonra içerik/token/DOM ya da JSON yapı karşılaştırması uygula. Uzunluk oranını tek başına karar vermeyen ucuz ön filtre olarak tut.

**Kod:** [modules/nginx_alias.go:152](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/modules/nginx_alias.go:152>).

### 11. P2 — CPDoS cache kanıtı aynı saniyedeki sıradan cevapları kabul ediyor

**Test:** `TestAuditCacheEvidenceAcceptsOrdinarySameSecondResponse`

Cache header'ı olmayan iki yanıtın Date ve body değerleri aynı olduğunda helper “cache hit” döndürdü.

Date/body eşitliği tek başına aradaki cache katmanını kanıtlamıyor. CPDoS akışındaki başka kontroller riski azaltıyor, ancak uygulama veya WAF'ın URL bazlı tekrar eden hata davranışı cache ile karıştırılabilir.

**Düzeltme:** Cache HIT/Age sinyalleriyle, bağımsız istemci isteğiyle ve zaman aralığı/TTL boyunca gözlenen kalıcılıkla birleştir. “Cache kaynağı belirsiz” sonucu açıkça ayrılmalı.

**Sınır:** Helper'ın yanlış kanıt kabulü gösterildi; tam CPDoS bulgusu bu testte üretilmedi.

**Kod:** [modules/cpdos.go:184](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/modules/cpdos.go:184>), [modules/cpdos.go:215](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/modules/cpdos.go:215>).

### 12. P2 — learning false-positive oranı gerçek bir oran değil

**Test:** `TestAuditLearning`

Aynı aileye 100 kez `OutcomeFalsePositive` kaydı yapıldı; `FalsePositiveRate` sonucu **0.00** oldu.

FP olayları benzersiz isim listesinde saklanıyor; toplam deneme sayısı olarak kullanılan Stability yalnızca bazı başka sonuçlarda artıyor. Başarı ve FP sayıları gerçek dağılımı temsil etmiyor. Ek olarak bu incelemede production candidate oluşturma yolunda `LearningFP` alanını dolduran bir atama bulunmadı.

**Düzeltme:** Aile/endpoint/modül sürümü bazında gerçek sayaçlar, örnek sayısı ve zaman ağırlığı tut. “Kanıt yetersiz”, “test çalışmadı” ve kullanıcı tarafından doğrulanmış false-positive ayrı etiketler olmalı. Kalibrasyon skora bağlanmadan önce ölçülmeli.

**Kod:** [learning/profile.go:55](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/learning/profile.go:55>), [learning/profile.go:85](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/learning/profile.go:85>), [modules/common.go:347](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/modules/common.go:347>), [modules/verification_probe.go:305](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/modules/verification_probe.go:305>).

### 13. P1 — coverage %100 denirken sıfır istek yapılabiliyor

**Test:** `TestAuditCoverageCountsSkippedTargetAsTested`

State/cleanup policy eksik bir POST hedefi için `parser_differential` çalıştırıldı.

Sonuç: **0 ağ isteği, targets_tested=1, coverage_percentage=100.0%**.

`testedCount`, modülün precondition/policy kontrolünden önce artırılıyor. Modüle gönderilen hedef sayısı gerçekten test edilen hedef sayısı olarak sunuluyor. Ayrı coverage-gap olayları bulunması bu yüzdeyi düzeltmiyor.

**Düzeltme:** `eligible`, `attempted`, `completed`, `verified`, `skipped_policy`, `skipped_capability`, `budget_exhausted`, `error` durumlarını ayrı say. Pasif analizler ağ isteği olmadan tamamlanabilir; metrik modülün gerçek terminal durumuna dayanmalı. Aktif kontrollerde “istek gönderildi” ile “kanıt sözleşmesi tamamlandı” da ayrılmalı.

**Kod:** [modules/module_runner.go:63](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/modules/module_runner.go:63>), [modules/module_runner.go:90](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/modules/module_runner.go:90>).

## İlave statik tespitler ve geliştirme alanları

### Global ağ bütçesi bütün taşıma yollarını kapsamıyor

HTTP WireTransport bütçe kontrolü var. Ancak `http_smuggling` doğrudan `net.Dialer` ve `io.WriteString` kullanıyor; browser süreçleri de aynı transport sayacını paylaşmıyor. Target seviyesindeki bütçe kontrolü, target içindeki fiziksel raw/browser isteklerini tek tek saymıyor.

Ortak budget/rate-limit hesabı ve protokole uygun tüketim API'si gerekiyor. Browser, normal HTTP ve raw TCP için ayrı görünür sayaçlar tutulmalı. Bu nokta kod akışıyla saptandı; bütçe aşımı için canlı ağ testi yapılmadı.

Kod: [httpclient/transport.go:31](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/httpclient/transport.go:31>), [modules/http_smuggling.go:190](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/modules/http_smuggling.go:190>), [browserpool/renderer.go:91](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/browserpool/renderer.go:91>).

### Bazı negatif testler adlarındaki senaryoyu gerçekleştirmiyor

`TestNginxOffBySlashWildcardRejection`, sonunda rastgele token bulunmayan sabit URL'ye yanıt ekliyor. Üretim kodu o URL'ye token eklediğinden mock eşleşmiyor; default 404 dönüyor. Fixture body uzunluğu da erken wildcard kontrolünün >100 koşulunu karşılamıyor. Testin “catch-all host” açıklaması ile gerçekleştirdiği davranış farklı.

Güvenli-negatif testlerde beklenen probe/control isteğinin gerçekten geldiğini de doğrulamak gerekir. Basit sıfır-bulgu assertion'ı, testin hiç çalışmadığı durumlarda da geçebilir.

Kod: [modules/new_active_modules_test.go:78](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/modules/new_active_modules_test.go:78>), [modules/nginx_alias.go:46](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/modules/nginx_alias.go:46>).

### Benchmark mevcut; tüm modüllerin doğruluğunu temsil etmiyor

CI'da race detector, unit/integration testleri ve strict observed benchmark zaten var. Bunları yeniden “eklenecek özellik” diye saymak doğru olmaz.

Benchmark'ın genişletilmiş negatif varyasyon döngüsü XSS, SQLi, SSRF ve LFI etrafında. JSONP, LLM, route auth, parser ve CSWSH için yukarıdaki güvenli örneklerin benchmark'a alınması gerekir. Aynı handler'ın çok sayıda varyantı bağımsız ürün/altyapı çeşitliliği anlamına gelmez.

Modül bazında precision/recall, yanlış pozitif sayısı, kaçırılan pozitif sayısı, tamamlanan proof oranı, request/kanıt maliyeti ve capability eksikliği raporlanmalı. Ortak toplam puanın zayıf modülü gizlemesine izin verilmemeli.

Kod: [benchmark/lab.go:77](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/benchmark/lab.go:77>), [benchmark/lab.go:115](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/internal/benchmark/lab.go:115>).

## Projeyi bir üst seviyeye taşıyacak sıralama

1. **Bulgu doğruluğu:** İlk beş modülün kanıt sözleşmesini düzelt. Normal özellik, keşif, şüpheli davranış ve doğrulanmış güvenlik etkisi net ayrılmalı. Severity, confidence ve verification status ayrı anlamlar taşımalı.
2. **Kaçırılan açıklar ve replay:** CORS, second-order, raw smuggling ve finding replay yollarını düzelt. Her pozitif senaryo için “açık bulundu → hedef düzeltildi → yeniden test fixed” zinciri kurulmalı.
3. **Dürüst kapsam görünümü:** Endpoint × method × parameter × role × module matrisi; atlama nedenleri ve eksik policy/capability listesi. Son kullanıcı hangi alanın gerçekten test edildiğini görebilmeli.
4. **Bağımsız doğruluk korpusu:** Public JSONP/WS, LLM refusals, SPA fallback, aynı uzunlukta farklı JSON, session expiry, cache'siz URL bazlı hatalar, origin varyantları gibi güvenli örnekler ekle. Pozitif ve negatif fixture'lar birlikte koşmalı.
5. **Tek modül sözleşmesi:** Manifest, dispatcher, sıralama, kategori ve proof-policy'nin farklı yerlerde elle tutulmasını azalt. Registry kaydı runner, capability, safety ve proof metadata'sını birlikte taşısın. `smuggling`/`http_smuggling` türü drift derleme/test aşamasında yakalansın.
6. **Policy hazırlamayı kolaylaştır:** Zaten bulunan identity/state/cleanup sözleşmeleri için doğrulanan örnekler ve yapılandırma hazırlama akışı ekle. Kaynak sahibi, yabancı rol, anonim kontrol, state okuma ve cleanup önceden kontrol edilsin.
7. **Ölçülen performans:** Yeniden yüklenen hedef envanterini discovery sürümüne göre cache'le; doğrulama isteklerinin ve fiziksel ağ denemelerinin maliyetini göster; browser/raw TCP bütçelerini birleştir. Her hız iyileştirmesinde aynı korpusta recall korunmalı.

Önerilen iş paketleri: önce 1–5 ve 9; ardından 6–8 ve 13; sonra 10–12, benchmark çeşitliliği ve registry sadeleştirmesi. Maskeleme bu yol haritasında yoktur.

## Doğrulama ve dosyalar

- `go test ./...`: başarılı; paketlerin çoğu Go test cache'inden geldi. Tam çıktı [go-test.log](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/docs/reviews/2026-09-09/go-test.log>).
- `go vet ./...`: başarılı.
- `go test ./internal/modules -run '^TestAudit' -v -count=1`: 13 yeniden üretim testi başarılı. Çıktı [reproductions.log](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/docs/reviews/2026-09-09/reproductions.log>).
- İlk yeniden üretim derlemesi varsayılan GOCACHE konumundaki erişim engeline takıldı; geçici klasörde ayrı GOCACHE ile tekrar çalıştırıldı ve tamamlandı.
- Race detector bu incelemede yeniden koşturulmadı; mevcut CI tanımı incelendi.
- Çalıştırılan testlerin kaynak kopyası [reproductions_test.go.txt](<C:/Users/caner/OneDrive/Masaüstü/Akca/engine/docs/reviews/2026-09-09/reproductions_test.go.txt>). Gofmt sonrası arşivlendiği için logdaki satır numaraları kaynak kopyasıyla birebir aynı olmayabilir.
- Yeniden çalıştırmak için kaynak kopyası geçici olarak `engine/internal/modules/z_audit_temp_test.go` adıyla yerleştirilip yukarıdaki test komutu çalıştırılabilir. Mevcut davranışı doğrulayan bu testler düzeltme sonrası beklenen güvenli davranışı assert eden kalıcı regresyon testlerine çevrilmelidir.
- Üretim kodu değiştirilmedi. İnceleme için eklenen geçici Go test dosyası kaldırıldı; sadece bu rapor ve kanıt dosyaları eklendi.

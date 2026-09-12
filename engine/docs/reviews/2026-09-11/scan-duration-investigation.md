# XSS / SQL tarama süresi incelemesi

Tarih: 2026-09-11. İncelenen kaynak: mevcut çalışma ağacı. Kullanıcının gerçek tarama komutu, hedefi ve koşu logu sağlanmadığından o koşunun kesin nedeni belirlenmedi.

## Sonuç

Birkaç saniyede bitmek tek başına hata değildir. Ancak normal tarama yolunda hedef atlanmasına ve eksik testin tamamlanmış sayılmasına yol açan iki davranış kontrollü olarak yeniden üretildi.

### 1. Modülün ortak kotası sonraki endpoint'i testsiz bırakabiliyor

`internal/modules/runner.go:256` XSS için hedef sayısı × 20, SQLi için hedef sayısı × 24 istek hesaplıyor. `InitModuleBudgetsFromTargets` bu kotayı `RequestBudget=0` iken de kuruyor. `canModuleProbe` genel bütçenin sınırsız olup olmadığını kontrol etmeden önce modül kotasını uyguluyor.

Bu bir hedef başına ayrılmış kota değil; modülün bütün hedeflerinin tükettiği ortak havuz. Erken hedefler havuzu bitirebiliyor. Varsayılan XSS fallback listesi tek güvenli hedefte baseline dahil 61 isteğe ihtiyaç duyuyor.

Normal uygulamanın çağırdığı `RunModuleFromDB` ile, yerel SQLite envanterine üç query parametreli endpoint eklenerek test edildi. HTTP cevapları deterministik test istemcisinden geldi; dış sisteme trafik gönderilmedi. Tek worker kullanıldı:

| Endpoint | Gönderilen istek |
|---|---:|
| /a-safe?q=hello | 61 |
| /b-safe?q=hello | 59 |
| /vulnerable?q=hello | 0 |

Loader üç parametre hedefi ve üç endpoint hedefi oluşturdu: toplam kota 6 × 20 = 120. Açıklı endpoint'e hiç istek gitmedi; bulgu sayısı 0 oldu. Olay kaydı `targets_total=6`, `targets_tested=2`, `targets_budget_exhausted=4` verdi. Worker sayısı ve hedef sırası dağılımı değiştirir; bu ölçüm her koşu için aynı sayıları iddia etmez.

Ayrı pozitif kontrolde iki parametre hedefiyle aynı açık endpoint test edildi: kota kurulmadan güvenli hedefe 61, açıklı hedefe 9 istek gönderildi ve 1 XSS bulundu. Üretimdeki kota kurulunca ilk hedef 40 isteği tüketti, açıklı hedefe 0 istek gitti ve 0 bulgu çıktı.

### 2. Hedef ortasında kota dolunca eksik test tamamlanmış sayılabiliyor

Tek parametreli güvenli hedef üzerinde aynı modül, aynı cevaplar ve aynı ayarlar kullanıldı; sadece üretimde uygulanan hedefe bağlı kota açılıp kapatıldı:

| Modül | Kota kurulmadan istek | Kota ile istek | Kota ile rapor |
|---|---:|---:|---|
| XSS | 61 | 20 | targets_tested=1, coverage_percentage=100.0%, targets_budget_exhausted=0 |
| SQLi | 60 | 24 | targets_tested=1, coverage_percentage=100.0%, targets_budget_exhausted=0 |

`common.go:25` modül kotasında HTTP isteği gönderilmeden hata dönüyor. Bazı probe yolları bunu boş sonuç olarak geçiriyor. `module_runner.go:87` daha önce başarılı bir HTTP cevabı görülmesini tamamlanma için yeterli sayıyor. Bütçe sayacı ise hedefe başlamadan yapılan kontrolde artıyor. Sonuç: hedef başladıktan sonra kesilen payload/teknik kapsamı bu sayaçta görünmüyor.

Buradaki yüzde hedef kapsamı metriği; bütün payload'ların işlendiğini kanıtlamıyor. Buna rağmen kesilmiş hedefin tamamlandı sayılması ve kota kesintisinin sıfır görünmesi tanılamayı yanıltıyor.

## Kısa süre için normal açıklamalar

- `TestFullLabScanQuick`: PASS, 0.53 saniye, 258 HTTP isteği; XSS ve SQLi dahil beklenen açık sınıfları bulundu.
- `TestLabSQLiPersistedFinding`: PASS, 0.06 saniye; SQLi bulgusu veritabanına kaydedildi.
- XSS ve SQLi, doğrulanmış bulgu kaydedildiğinde o hedef için erken dönebiliyor.
- Parametresiz endpoint, bu iki modülde enjeksiyon yüzeyi sağlamıyor ve istek gönderilmeden atlanıyor.
- SQLi zaman tabanlı payload'ının hedefte gecikme üretmemesi, tarayıcının payload'daki süre kadar beklemesini gerektirmiyor. Mevcut negatif scout testi bu davranışı kapsıyor.

Lab testinin geçmesi normal tarama kapsamını garanti etmiyor: `testlab/targets.go:17` bilinen hedefleri ekliyor, `testlab/pipeline.go:310` URL yoluna göre sınırlı modül çalıştıran `RunIntegrationSubset` kullanıyor. Normal uygulama ise `RunModuleFromDB` kullanıyor ve hedefe bağlı modül kotalarını kuruyor.

## Çalıştırılan kontroller

Engine klasöründe:

```text
go test ./internal/testlab -run 'TestLabSQLiPersistedFinding|TestFullLabScanQuick' -count=1 -v -timeout 4m
go test ./internal/modules -run '^TestDiagnosticScanDurationCoverage$' -v -count=1 -timeout 60s
go test ./internal/modules -run '^TestDiagnosticProductionLoaderStarvation$' -v -count=1 -timeout 60s
```

Tanı testleri mevcut davranışı ölçmek için çalıştırıldı; PASS, hatanın düzeltildiği anlamına gelmez. Kaynakları bu klasörde `scan-duration-repro_test.go.txt` olarak saklandı; normal test paketinde bırakılmadı. Yeniden çalıştırmak için bu kaynak geçici olarak `internal/modules/scan_duration_diagnostic_test.go` konumuna konabilir veya Go overlay kullanılabilir.

Üretim kodunda değişiklik yapılmadı. İnceleme başlamadan mevcut olan `loader.go`, `sqli.go`, `sqli_advanced.go`, `sqli_test.go` değişiklikleri korundu. Ölçümler bu çalışma ağacını yansıtır; kullanıcının çalıştırdığı binary'nin aynı sürüm olduğu doğrulanmadı.

## Düzeltmenin karşılaması gereken koşullar

Sınırsız ayarın hedefe bağlı gizli kota ile kesilmemesi; sınırlı taramada kalan endpoint'lere adil test payı ayrılması; hedef ortasındaki kota kesintisinin açıkça eksik kapsam olarak raporlanması. Regresyon kontrolü, normal DB loader ve modül akışı üzerinden önce güvenli sonra açıklı endpoint'leri kullanmalı. Bu incelemede düzeltme uygulanmadı.

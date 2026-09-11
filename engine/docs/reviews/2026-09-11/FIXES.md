# Denetim düzeltmeleri — 11 Eylül 2026

Bu kayıt, 9 Eylül tarihli AUDIT.md raporunun düzeltme devamıdır. Eski rapor ve yeniden üretim dosyaları tarihsel kanıt olarak korunmuştur. Maskeleme eklenmedi; HTTP istek/yanıtları, raw TCP istek baytları ve yeni tarayıcı veri okuma gözlemleri ham haliyle saklanır.

## Düzeltilen davranışlar

| Alan | Sonuç |
|---|---|
| Route auth bypass | Başarılı alternatif sayfa, oturumlu asıl kaynağa veya önceden tanımlanmış özel canary'ye bağlanır. İki bağımsız tekrar gerekir. Yazma yöntemleri ilk istekten önce elenir. |
| LLM injection | Ret mesajları ve genel sistem promptu benzerliği açık sayılmaz. İstekte gönderilmeyen, baseline'da bulunmayan özel canary'nin model yanıtında görülmesi gerekir. |
| JSONP ve CSWSH | Callback desteği, public kullanıcı alanları ve 101 handshake keşif olarak kalır. Açık için anonim tarayıcı kontrolü ve iki oturumlu cross-origin özel veri okuması gerekir. Custom header varlığı oturum kanıtı sayılmaz. |
| Parser differential | Sıradan duplicate-key kabulü keşiftir. Özel canary, ayrı izinli/yasak tek-anahtar kontrolleri ve tekrar gerekir. Ayrıcalıklı tek değer 401/403 ile reddedilmelidir. |
| CORS | Native baseline Origin içermez. Pozitif origin iki kez tekrarlanır, ayrı no-Origin kontrolü kullanılır. Same-origin, wildcard+credentials, iç ağ origin'i ve PNA başlığı tek başına veri hırsızlığı/SSRF olarak etiketlenmez. OAST probe yolu korunmuştur. |
| Second order | Gönderilmeyen sentetik takip işareti yerine gerçek DOM payload'ı izlenir. Boş sentetik baseline ve kopya gözlem kaldırıldı. Ham yanıtta bulunmayan tarayıcı execution işareti gerekir. |
| Raw HTTP smuggling | Normal HTTP replay yerine kontrol ve iki ayrı raw bağlantı kullanılır. Gönderilen baytlar korunur. Tek başına normal pipelining olan CL:0 varyantı açık kanıtı sayılmaz. |
| Finding replay | Hash, gövdeye ek olarak status ve modüle uygun güvenlik başlıklarını içerir. Yerel redirect testi önce still_vulnerable, Location düzeltmesi sonrası fixed verir. |
| Benzerlik | Aynı uzunluk yeterli değildir; normalize edilmiş içerik farkı karşılaştırılır. |
| CPDoS | Aynı Date/body cache kanıtı değildir. uncached gibi metinler hit sayılmaz; hit tokenları ve sayısal hit sayacı ayrılır. |
| Learning | Conclusive outcome sayaçları saklanır; oran FP/(FP+worked). Belirsiz doğrulama FP etiketi üretmez. Endpoint/domain sayımları iki kez birleştirilmez; eşzamanlı kayıtlar korunur. |
| Coverage | Başlangıçta target saymak yerine gerçekleşen istek/kanıt, skip ve hata durumları izlenir. Hiç probe yapılmayan target %100 tested görünmez. İşlenemeyen target sayısı ayrıca raporlanır. |
| Ağ bütçesi | HTTP retry/redirect ile browser HTTP, raw TCP, TLS ve H2 prober yolları ortak atomik bütçe/host limiter'a bağlanır. Bütçe reddi sayacı limiti aşacak şekilde şişirmez. Nil limiter çökmesi düzeltildi. |
| Test kalitesi | Hatalı Nginx wildcard fixture rastgele URL'yi gerçekten karşılar ve kontrol isteğinin geldiğini doğrular. İlk 13 regresyona pozitif özel veri, parser, raw transport, replay, sayaç ve iki ek negatif test eklendi. |

## Özel canary yapılandırması

Canary uygulamanın gerçekten özel tuttuğu, saldırı isteğine konulmayan bir değer olmalıdır. Aşağıdaki yalnızca örnek yapılandırmadır; gerçek hedefin test verisine göre doldurulur:

```json
{
  "content_proof_policies": [
    {
      "id": "chat-private-proof",
      "module": "llm_injection",
      "url_contains": "https://your-test-host.example/api/chat",
      "private_canary": "test-only-private-canary-71832"
    }
  ]
}
```

Desteklenen modüller: llm_injection, parser_differential, route_auth_bypass, jsonp_callback, ws_cswsh. En az 12 karakter, boş olmayan URL eşleştiricisi ve benzersiz ID doğrulanır. JSONP/CSWSH browser worker pool ve uygun oturum cookie'si de gerektirir. Canary/policy veya browser kanıtı yoksa gözlenen kabiliyet module_discovery olarak tutulur; bulgu sayısı şişirilmez.

## Doğrulamanın sınırları

- Cross-origin tarayıcı doğrulamasının pozitif/negatif sözleşmesi mock reader ile test edildi; gerçek Chromium + SameSite/üçüncü taraf cookie matrisi bu oturumda uçtan uca çalıştırılmadı. Tarayıcı hatası ve timeout negatif başarı kabul edilmez.
- Genel finding replay, browser/timing/OAST/runtime/raw-protocol kanıtlarını otomatik fixed/still_vulnerable diye yorumlamaz; özgün doğrulayıcı gerektiğini belirterek inconclusive döner. Bu doğrulayıcıların replay UI üzerinden yeniden başlatılması ayrı geliştirmedir.
- Browser Fetch guard HTTP(S) isteklerini, özel cross-origin WS okuyucu ise başlattığı bağlantıyı bütçeler. Sayfa JavaScript'inin kendiliğinden açtığı tüm WebSocket/WebRTC trafiği için tam ağ aracısı izolasyonu sağlanmış değildir.
- Strict benchmark sonucu mevcut yerel korpusa aittir; bütün gerçek ürün/altyapılarda %100 doğruluk anlamına gelmez. Yeni bağımsız negatif senaryolar Go regresyon testlerindedir; benchmark'ın tüm modül bazlı ürün çeşitliliği genişletilmedi.
- Registry'nin tamamen tek sözleşmeye dönüştürülmesi, policy hazırlama arayüzü ve discovery sürümüne göre inventory cache'i denetimde önerilen mimari geliştirmelerdir; bu düzeltmede uygulanmadı.
- Yerel race denemesi CGO/gcc gereksinimi nedeniyle çalışmadı. GCC bu ortamda bulunmuyor; mevcut Linux CI race gate korunuyor.

## Son doğrulama

- `go test ./... -count=1`: başarılı; son tam koşu cache kullanılmadan tamamlandı. Çıktı: go-test.log.
- `go vet ./...`: başarılı. Çıktı: go-vet.log (uyarı yok).
- `git diff --check` ve değiştirilen Go dosyalarının gofmt kontrolü: başarılı.
- Strict observed benchmark: başarılı; mevcut korpusta precision/recall/specificity/F1 = 1, FP oranı = 0; %95 FP üst sınırı = 0.043733. Ayrıntı: benchmark-quality.json. Bu sayı korpusun boyutuyla sınırlıdır.
- Race detector: çalıştırılamadı; CGO etkinleştirildiğinde gcc bulunamadı. Ayrıntı: race-unavailable.log.
- CLI pasif tarama entegrasyon testinin kullanıcı dizinine yazma bağımlılığı kaldırıldı. Geçici veri dizini override'ı önceki override oluşturulmadan/çözümlenmeden geri yüklenebilir; son tam test koşusunda CLI entegrasyonu da geçti.

Değişiklikler çalışma ağacındadır; commit veya dağıtım yapılmadı.

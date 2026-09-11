# Kullanıcı örneklerine dayalı düzeltmeler

Üçüncü taraf hedeflere canlı istek gönderilmedi. Paylaşılan HTTP örnekleri ve aynı davranışı üreten yerel fixture'lar kullanıldı. Önceki çalışma ağacı değişiklikleri korundu; maskeleme eklenmedi.

1. **CORS / GraphQL 400:** Hedefin trusted-sub alt alan adına izin vermesi saldırgan kontrolü göstermez. Bu sinyal doğrulama katmanında kabul edilmez. Başarısız HTTP yanıtlarındaki CORS başlıkları application-data bulgusu yerine keşif kaydıdır; pozitif tekrarlar da başarılı yanıt gerektirir. Genel olarak 400 yanıtı her koşulda güvenlidir iddiası yoktur; paylaşılan hata sayfası özel veri okunmasını kanıtlamaz.
2. **Open redirect:** Location içinde evil.example sözcüğü aramak kaldırıldı. Navigasyon URL'sinin gerçek authority/hostname alanı kontrol edilir; nested query, kullanıcı bilgisi veya path içindeki metin hedef sayılmaz. l.facebook.com üzerinden www.facebook.com adresine taşınan extra_1 parametresi artık pozitif değildir. Gerçek external-host yönlendirmeleri için pozitif kontroller vardır. HTTP yönlendirmesinde javascript/data metni çalıştırılmış JavaScript kanıtı sayılmaz.
3. **CSTI:** alert(1) kaynak metni execution tokenı olarak kaldırıldı. HTTP gövdesindeki aritmetik sonuç frontend yürütmesi olarak sınıflanmaz. CSTI bulgusu için raw HTML'de olmayan benzersiz kök DOM niteliği, browser kontrolü ve tekrar gerekir. Header/POST yüzeyini yalnızca GET URL'sini render ederek doğrulama yapılmaz; desteklenmeyen yüzey açık atlama nedeni üretir.
4. **Client prototype pollution:** __proto__/prototype gibi yanıt metinleri Object.prototype mutasyonu sayılmaz. Client payloadlarının yalnızca HTTP yanıtını değiştirmesi keşif olarak saklanır. Genel prototype_behavior_change ve hata metni, ortak kanıt kontrolünden geçemez. Bu değişiklik tam browser prototype-mutation doğrulayıcısı eklemez; ispatlanamayan istemci bulguları confirmed olmaz.
5. **Route .json:** Önceki özel kaynak bağlama düzeltmesine, herkese açık kategori sayfası + User-Agent/header senaryosu eklendi. Native anonim 200 yanıtında modül tek kontrol isteği sonrası durur; aynı sayfanın .json görünümü bypass sayılmaz.
6. **Copy Response:** Düğmenin kardeşi yerine .code-header öğesinin ardından gelen pre bulunur. textContent ile vurgulama etiketleri değil ham yanıt kopyalanır. Clipboard API yoksa veya reddedilirse textarea/execCommand yedeği denenir. Her iki yol başarısızsa başarı bildirimi gösterilmez. Aynı düzeltme Copy Request ve Copy cURL düğmelerine de uygulanır.

## Kullanım

Kökteki ve engine altındaki eski akca.exe dosyaları 8 Eylül derlemeleriydi. İkisi de yeniden derlenmiş aynı executable ile güncellendi; SHA-256: 8A3D198EDE4B15A778ED979B3AC0D044ABA204FB40E9EA9E8A5ABFF4B473F9D3. Yeni HTML raporları düzeltilen JavaScript'i içerir; daha önce dışa aktarılmış HTML dosyaları kendi eski scriptlerini taşıdığı için yeniden oluşturulmalıdır. Önceden kaydedilen bulgular bu değişiklikle otomatik silinmez veya yeniden sınıflandırılmaz.

## Testler

- user_fp_regression_test.go: nested Location, gerçek external redirect, CORS 400, trusted-sub, literal alert, prototype text, public route ve pozitif/negatif CSTI browser sözleşmesi.
- clipboard_test.go + testdata/clipboard_test.cjs: gerçek şablondaki JavaScript dört Clipboard API/izin senaryosuyla Node VM içinde çalıştırılır; ham metin korunur. Sistem panosu değiştirilmez.
- CSTI pozitif testi mock renderer kullanır; canlı üçüncü taraf veya gerçek Angular tarayıcı testi yapıldığı iddia edilmez.

Son doğrulama: `go test ./... -count=1` (80 başarılı paket), `go vet ./...`, `git diff --check` ve executable `--version` kontrolü başarılı. Loglar: user-fp-go-test.log, user-fp-go-vet.log.

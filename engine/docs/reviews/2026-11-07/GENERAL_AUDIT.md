# AKCA genel inceleme — 7 Kasım 2026

## Kapsam

Tarama yaşam döngüsü, crawler, parametre keşfi, HTTP/kapsam sınırı, modül kataloğu,
kanıt politikası, depolama, raporlama, CLI ve yerel benchmark testleri incelendi.
Kod tabanında 88 Go paketi ve katalogda 92 çalıştırılabilir güvenlik modülü var.

## Doğrulanıp düzeltilen sorunlar

- Gizli parametre aday sınırı, kök JSON uçlarında `admin` adını liste dışına
  itebiliyordu. Yüksek değerli adaylar arasına geri alındı. GET → POST JSON
  keşif entegrasyon testi yeniden geçti.
- Parametre ilerleme testi, artık kasıtlı olarak aktif tahminden çıkarılan
  sıradan HTML kök URL'sini kullanıyordu. Test, gerçek bir `/api/search` yüzeyini
  kullanacak şekilde güncellendi; ilerleme olayı ve keşif doğrulandı.
- Benchmark laboratuvarı yerel Chrome kurulumunu açık tercih olmadan
  kullanabiliyordu. Gerçek browser artık yalnızca
  `AKCA_RUN_REAL_BROWSER_TESTS=1` ile etkinleşiyor.
- Kısa benchmark taramasında küçük crawl bütçesi ve eşzamanlı işçiler farklı
  örnek URL'lere yol açabiliyordu. Laboratuvarın kısa crawler örneklemesi seri
  çalışacak şekilde sabitlendi. Paralel kısa test paketi iki ardışık koşuda
  geçti. Bu değişiklik üretim crawler eşzamanlılığını değiştirmiyor.

## Doğrulama

- `go vet ./...`: geçti.
- `gofmt -l .` ve `git diff --check`: temiz.
- `go test ./... -p 1 -count=1 -timeout=180s`: tüm paketler geçti.
- `go test ./... -short -count=1 -timeout=120s`: son değişikliklerden sonra
  varsayılan paralel koşuda iki kez geçti.
- `go test ./internal/modules -cover -count=1`: geçti; ifade kapsamı **%64,9**.
- Testler kendi açtıkları yerel HTTP sunucularına bağlandığı için ağ izniyle
  çalıştırıldı. Kısıtlı sandbox içindeki bağlantı reddi kod hatası sayılmadı.

## Kalan doğrulama boşlukları

Tam modül korpusu kalite kapısı geçmiyor: 92 modülün yalnızca **13** tanesinde
hem pozitif hem negatif gözlenen fixture var. **79** modülde pozitif, **75** modülde
negatif fixture eksik; browser yeteneği gerektiren bir senaryo bu ortamda
atlanıyor. Mevcut gözlenen korpusta precision `1.0`, recall `0.9286`; bu değerler
diğer modüllerin doğruluğunu kanıtlamıyor.

Windows ortamında `CGO_ENABLED=0` ve C derleyicisi yok; `go test -race` bu
ortamda çalıştırılamadı. Canlı veya staging hedefte yetkili uçtan uca tarama
ve performans ölçümü yapılmadı. Bu nedenle sıfır hata veya sıfır yanlış pozitif
garantisi verilemez. Sonraki doğrulama işi, eksik modül fixture'larını ve
eşzamanlılık testlerini tamamlamaktır.

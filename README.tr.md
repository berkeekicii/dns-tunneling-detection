# DNS Tunneling Detection — Minimum Demo (Offline)

[English](README.md) | **Türkçe**

Bu demo, kayıtlı PCAP dosyası üzerinden DNS tünellemesini analiz eder, NDJSON formatında alarm üretir ve “5 kötü / 5 iyi” senaryosunu otomatik doğrular. NDJSON satır-başı JSON yapısı sayesinde satır başına tek olay saklanır ve akış işleme ile uyumludur.

> **ONNX Runtime kurulumu:** ML skoru için `onnxruntime.dll` gerekir ve depoda bulunmaz. [ONNX Runtime v1.22.1](https://github.com/microsoft/onnxruntime/releases/tag/v1.22.1) sayfasından `onnxruntime-win-x64-1.22.1.zip` dosyasını indirip `runtime/onnx-1.22.1/` altına açın; DLL şu yolda olmalıdır: `runtime/onnx-1.22.1/onnxruntime-win-x64-1.22.1/lib/onnxruntime.dll`.

1) Test Dosyaları (repo içinde)

data/dns-lab-10q.pcapng
→ Demo PCAP: 5 “kötü” (alarm beklenen) + 5 “iyi” (alarm beklenmeyen) sorgu içerir.

data/dns-lab-10q.json
→ Karşılaştırma listesi: “bad” ve “good” adlarının referans seti (assert betiği bunu okur).

config/demo.toml
→ Eşikler ve whitelist (örn. min_entropy, min_domain_len, txt_ratio, nxdomain_ratio, qps_client, unique_sub_ratio).

scripts/assert-5v5.ps1
→ Otomatik doğrulama: “5 kötü = alarm var”, “5 iyi = alarm yok”, ayrıca ≥3 farklı reason kontrolü.

target/alerts.ndjson
→ Analiz çıktısı (satır başına tek JSON kayıt). NDJSON = “Newline Delimited JSON”. 


Not: “Kötü” isimler .invalid TLD’si kullanır; bu TLD özel-kullanım için ayrılmıştır ve isteklerin NXDOMAIN dönmesi beklenir — test için güvenli/tekrarlanabilir davranış sağlar. 


2) Nasıl Çalıştırılır? (Sadece Kayıtlı Trafik)
# 1) Analiz
$pcap = ".\data\dns-lab-10q.pcapng"
cargo run --bin cli -- --mode batch --pcap "$pcap" --config "config\demo.toml" --out "target\alerts.ndjson"

# 2) Hızlı özet (isteğe bağlı)
Get-Content "target\alerts.ndjson" | ConvertFrom-Json |
  Sort-Object score -Descending |
  Format-Table qname, @{n='score';e={"{0:N2}" -f $_.score}}, reasons

# 3) Otomatik doğrulama (başarı beklenen çıktı)
powershell -ExecutionPolicy Bypass -File .\scripts\assert-5v5.ps1
# ÖZET -> badOK:True  goodOK:True  reasonVariety(>=3):True



3) Beklenen Davranış / Başarı Kriteri (Offline)

5 “kötü” alan için alarm üretilir (farklı “reasons” kombinasyonlarıyla).

5 “iyi” alan alarm üretmez.

En az 3 farklı reason kombinasyonu görülür (örn. len+entropy, txt_ratio, nxdomain_ratio, qps_client, unique_sub_ratio).

4) SSS (Kısaca)

Neden .invalid?
Çatışma ve karışıklığı önlemek için özel-kullanım amacıyla ayrılmıştır; sorguların NXDOMAIN dönmesi öngörülür → etik, güvenli ve tekrarlanabilir test. 


NDJSON nedir?
Satır-başı JSON biçimi: her satır tek bir JSON nesnesi; akış/boru hattı işleme ve büyük veri için pratik.
## Uçtan Uca Pipeline (Açıklamalı)

Bu bölüm, projenin “yakalama → dönüştürme → analiz → rapor” zincirini sade ama ayrıntılı biçimde anlatır. Hedef; hem staj komisyonunun hem de yeni katılan bir mühendisin, tek başına bu metni okuyarak sistemi çalıştırabilmesi, sonuçları doğrulayabilmesi ve kanıt (evidence) üretebilmesidir. Kod dosyalarını değiştirmeden tamamen manuel yürütmek mümkündür; komutlar ve ekran görüntüsü ipuçları bu amaçla hazırlanmıştır.

### 1) Trafiği Yakalama (opsiyonel; demo için hazır PCAP var)

- Windows’ta yerleşik `pktmon` aracıyla DNS (UDP/53) trafiği yakalanabilir. Depoya dahil `scripts/capture-with-pktmon.ps1` betiği, filtreyi açar, kısa bir kullanım simüle eder ve kaydı durdurup ETL’yi `.pcapng`’e dönüştürür. Bu betiği çalıştırmak için PowerShell’i Yönetici (Run as Administrator) açmak gerekir.
- Demo ve kanıt süreci için “hazır” dosyalar mevcuttur: `data/dns-lab-10q.pcapng` (kısa, içinde hem kötü hem iyi örnekler var), `data/good-normal.pcapng`, `data/good-spotify.pcapng`. Böylece canlı yakalama zorunluluğu yoktur.
- Canlı akış (stream) modu gelecekte genişletilebilir; bu depo öncelikle offline/PCAP analizi içindir.

### 2) Dönüştürme (ETL → PCAPNG)

- Eğer yakalamayı siz yaptıysanız, `pktmon start/stop` sonrası oluşan `PktMon.etl` dosyası `pktmon pcapng PktMon.etl -o data\live-<ts>.pcapng` ile `.pcapng` formatına çevrilir. Platform bu komutu desteklemiyorsa `pktmon etl2pcap` kullanılabilir.
- Üretilen dosyayı `Test-Path data\live-<ts>.pcapng` ile doğrulayın; devamında CLI analizi bu dosya üzerinden yapılır.

### 3) Analiz Motoru (Rust CLI)

- Temel komut kalıbı:
  - `cargo run --bin cli -- --mode batch --pcap <dosya.pcapng> --config config\demo.toml --out target\alerts.ndjson`
- Bayraklar:
  - `--pcap`: Analiz edilecek PCAP/PCAPNG dosyası.
  - `--config`: Eşik/whitelist/ML ayarları.
  - `--out`: NDJSON çıktı yolu (her satır bir alarm JSON).
  - `--suppress-secs N`: Aynı `(root,qtype)` için tekrar uyarı bastırma penceresi; varsayılan 60 sn. Bu, “aynı kökten üst üste alarmlar”ı tek satıra indirir.
- İç mantık (özet): `crates/cli/src/main.rs` PCAP kayıtlarını okur, her DNS olayı için özellikleri çıkarır (feature engineering) ve iki paralel karar kaynağını çalıştırır: (1) eşik bazlı kural motoru, (2) ML (Isolation Forest). Son kararda OR birleştirme kullanılır: “ALARM = kural tetiklendi ∨ ML anomali dedi”. Whitelist’e takılan köklerden alarm üretilmez.

#### 3.1 Özellik Vektörü (x7)

Her DNS kaydından çıkarılan 7’li vektör:
- `domain_len`: Alan adının uzunluğu
- `shannon_entropy (H)`: Karakter çeşitliliği ve düzensizlik ölçüsü
- `label_count`: Etiket sayısı (a.b.c → 3 gibi)
- `txt_ratio`: Pencere içinde TXT oranı
- `nxdomain_ratio (nx)`: NXDOMAIN/servfail oranı
- `qps_client (qps)`: İstemci başına saniye başına sorgu
- `unique_sub_ratio (uniq_sub)`: Aynı pencerede benzersiz alt-ad oranı

Not: Pencere metrikleri (ratio alanları) içeride şimdilik sabit 60 saniyelik bir pencere ile hesaplanır. Bu, ileri sürümlerde parametreleştirilebilir. `--suppress-secs` bundan bağımsızdır; o tekrar alarm bastırma penceresidir.

#### 3.2 Whitelist

- `config/*.toml` içindeki `whitelist.domains` (ör. `spotify.com`, `.arpa`) eşleşirse, kural ve ML değerlendirmeye girse bile alarm yazılmaz. Eşleşme ASCII-case-insensitive son ek (suffix) olarak değerlendirilir.

#### 3.3 Kural Motoru (rules)

- `crates/rules` modülü, `Thresholds` yapılandırmasına göre puan toplar ve her eşiği geçen kriteri `reasons` listesine ekler. Örnek etiketler: `len>=min`, `entropy>=min`, `txt_ratio>=min`, `nxdomain_ratio>=min`, `qps>=min`, `unique_sub>=min`.
- Kural puanı toplamı `score_alert` eşiğini geçtiğinde “kural tetiklendi” sayılır.

#### 3.4 ML Skoru (ONNX Isolation Forest)

- Model: `models/iforest.onnx`. ONNX Runtime dosyaları `runtime/onnx-1.22.1/...` altında versiyonlanmıştır.
- `MlIf` sarmalayıcısı modeli tembel (lazy) şekilde yükler, her kayıt için `x7` vektörünü skorlar. `ml.score_threshold` ile kıyaslayarak “anomali mi?” kararını üretir. Anomali ise `reasons` listesine `ml_iforest` etiketi eklenir ve `reason` alanı `ml`/`both` olabilir.

#### 3.5 Karar ve Bastırma

- OR mantığı: “ALARM = (kural_tetiklendi) ∨ (ml_is_anomaly)”.
- Dedup/suppress: `--suppress-secs` ile belirlenen kovalar (bucket = `event_ts / N`) içinde aynı `(root,qtype)` için tek alarm yazılır. Bu sayede gürültü kontrol edilir. 5 sn’de tekrarlar daha çabuk görünür (adet artabilir), 30 sn’de daha seyrek görünür (adet azalabilir).

#### 3.6 NDJSON Çıktısı

- Her satır tek JSON: `ts`, `mode`, `score`, `reason` ve `reasons` (etiketler) ile birlikte DNS alanları (`qname`, `root`, `qtype`) ve özellikler (`domain_len`, `entropy`, `txt_ratio`, `nx_ratio`, `qps_client`, `unique_sub_ratio`). ML varsa `ml_score` ve `ml.threshold` de yazılır.

### 4) Raporlama (HTML/PDF)

- `tools/report_html.ps1` NDJSON’u okuyup `target/report.html` üretir. Başta toplam alarm, farklı kök sayısı, etiket çeşitliliği, ML eşiği gibi özetler; tabloda ise her alarmın detayları ve etiket pill’leri yer alır.
- PDF ihtiyacı varsa Edge/Chrome ile “PDF olarak yazdır” veya headless `--print-to-pdf` kullanılabilir. Sunumlarda ilk sayfayı ekran görüntüsü almak en pratik yöntemdir.

### 5) Olay Zenginleştirme (incidents)

- `tools/render_incidents.ps1` `target/alerts.ndjson` üzerinden `target/incidents.ndjson` yazar ve şu meta alanları ekler: `model_sha256`, `build_id` (exe ProductVersion / git SHA / exe SHA-256 kısa), `ort_version`, maske IP’ler (`src_ip_masked`, `dst_ip_masked`).
- Bu dosya; izlenebilirlik, teslim öncesi denetlenebilirlik ve model/sürüm eşleşmesini kanıtlamak için idealdir.

### 6) Manifest Çalıştırma (çoklu senaryo)

- `tests/manifest.ndjson` içine her satır `{"name","pcap","label","config"}` alanlarıyla bir iş tanımıdır.
- `tests/run_manifest.ps1` bu listeyi döner, her senaryo için CLI’ı çalıştırır, `report.html` ve varsa PDF üretir. Sonda kısa bir özet tablo basar ve son raporu `target/report.html` olarak kopyalar (IDE’de hızlı görüntüleme için).

### 7) Yapılandırma (TOML)

- `config/demo.toml` demo eşiği/whitelist ayarlarını içerir. Örnekler:
  - `min_domain_len`, `min_entropy`, `min_txt_ratio`, `min_nxdomain_ratio`, `min_qps_client`, `min_unique_sub_ratio`
  - `ml.mode = "onnx"`, `ml.model_path`, `ml.score_threshold`
- Not: İç özellik penceresi şu an sabit 60 saniyedir; `--suppress-secs` tekrar alarm bastırma penceresidir. İkisi farklı kavramlardır.

### 8) Dosya Adlandırma ve Yapı

- Analiz çıktısı: `alerts.<senaryo>.ndjson` (tek koşu için `target/alerts.ndjson`).
- Rapor: `report_<senaryo>.pdf` ve/veya `report.<senaryo>.html`.
- Olay: `target/incidents.ndjson`.
- Model/Runtime: `models/`, `runtime/onnx-1.22.1/...`.

### 9) Kanıt (Screenshot) Seti – Jüri İçin

- Terminal: çalıştırdığınız komut + kısa çıktı (aynı karede). Örn. `cargo run ...` sonrası `[OK] MODE=batch | pcap=... | config=...` ve `Get-Content ... | Measure-Object` ile alarm adedi.
- Rapor: `report.html` ilk sayfanın ekran görüntüsü; “Total alerts”, “Top roots”, “Reason distribution”, ve tablo başı görülür.
- Incidents: `tools\render_incidents.ps1` sonrası “OK: wrote target\incidents.ndjson” ve dosyanın ilk 1–3 satırı (model/build/ort sürümü) ekrana getirilip kadrajlanır.
- Sürüm/İzlenebilirlik: `git rev-parse --short HEAD` ve `(Get-FileHash models\iforest.onnx -Algorithm SHA256).Hash` çıktıları.
- Ayar görünürlüğü: `config\demo.toml` içindeki kritik satırlar; dosyayı sadece görüntüleyin (değiştirmeyin), ekran görüntüsü alın.

### 10) Tekrarlanabilirlik ve Doğrulama

- Aynı PCAP ve config ile çalıştırıldığında skor ve etiketler aynıdır; NDJSON’daki `ts` alanı sistem zamanına bağlıdır ve doğal olarak farklı olabilir.
- `scripts/assert-5v5.ps1` laboratuvar listesine göre otomatik doğrulama yapar: kötülerin alarm vermesi, iyilerin vermemesi, en az 3 farklı reason kombinasyonu beklenir.

### 11) Performans ve Sınırlar

- Bu demo okunabilirlik ve denetlenebilirlik önceliğiyle yazılmıştır. Yük altında ek optimizasyonlar (paralel okuma, batch inference, I/O iyileştirmeleri) değerlendirilebilir.
- Kök alan (root) çıkarımı basit eTLD+1 yaklaşımıdır; üretim sistemlerinde Public Suffix List ile zenginleştirme önerilir.
- Pencere süresi içte sabittir; gelecekte CLI parametresi ile değiştirilebilir hale getirilmesi planlanabilir.

### 12) Sorun Giderme

- `pwsh` tanınmıyor: Windows PowerShell içindeyseniz betikleri `.<yol>\script.ps1` ile çalıştırın; gerekirse `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`.
- ONNX Runtime yüklenemedi: `runtime/onnx-1.22.1/.../onnxruntime.dll` yolunu ve mimariyi doğrulayın.
- PDF üretilmedi: Edge/Chrome bulunamazsa tarayıcıda açık `report.html` için “PDF olarak yazdır” kullanın.
- 5s/30s karşılaştırması fark göstermiyor: PCAP’ınızda aynı `(root,qtype)` için tekrar eden olay yok olabilir; tekil olayda bastırma penceresi doğal olarak fark yaratmaz.

### 13) Hızlı Başlangıç – Kötü/İyi Örnekler

1) Kötü (lab):
- `cargo run --bin cli -- --mode batch --pcap data\dns-lab-10q.pcapng --config config\demo.toml --out target\alerts.bad_exfil_demo.ndjson`
- `./tools/report_html.ps1 -alerts target\alerts.bad_exfil_demo.ndjson -out target\report.bad_exfil_demo.html`

2) İyi (normal):
- `cargo run --bin cli -- --mode batch --pcap data\good-normal.pcapng --config config\demo.toml --out target\alerts.good_normal.ndjson`
- `./tools/report_html.ps1 -alerts target\alerts.good_normal.ndjson -out target\report.good_normal.html`

### 14) Sunum ve Teslim İpuçları

- Jüriye tek sayfada net görünür kareler verin: komut+çıktı, rapor ilk sayfa, incidents ilk satırlar, config kritik satırlar. Dosya adlandırma uyumunu (alerts.<senaryo>.ndjson / report_<senaryo>.pdf) Dosya Gezgini görüntüsüyle gösterin.
- Tekrarlanabilirliği göstermek için aynı “kötü” analizi iki kez çalıştırın; “label count” ve “most frequent combination” çıktılarının bire bir aynı geldiğini yakalayın.

### 15) Güvenlik ve Gizlilik

- IP’ler incidents’ta maskelenir (IPv4 son oktet `x`, IPv6 `::x`). `.invalid` TLD test amaçlıdır; gerçek sistem adlarıyla karışmaz.

### 16) Yol Haritası

- Analiz penceresinin CLI ile ayarlanabilmesi (5s/10s/30s gibi) ve raporda görünür hale getirilmesi.
- Karar mantığında AND/OR/ağırlıklı birleşimler ve kalibrasyon araçları.
- Whitelist/blacklist’in merkezi yönetimi; canlı izleme panelleri; çoklu model desteği.

Bu metin, projenin uçtan uca mimarisini, karar mekanizmasını ve kanıt üretme biçimini tek yerde toplar. Aynı girdilerle aynı sonuçları üreten, manuel ekran görüntüsüyle kolayca kanıtlanabilen bir akış sunar: “yakalama → dönüştürme → analiz → rapor”.

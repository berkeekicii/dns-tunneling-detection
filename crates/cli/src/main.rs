// crates/cli/src/main.rs
// Not: Yorumlarda basit dil + parantez içi tanım kullanıldı.

use anyhow::Result;

#[allow(unused_imports)]
use collector::PacketSource; // (ileride canlı trafik/stream için arayüz kaynağı)

use clap::{Parser, ValueEnum}; // (komut satırı argümanları)
use collector::PcapReader; // (pcap dosyasını okuyan basit reader)
use features::{FeatureVector, WindowState}; // (DNS özelliklerini çıkaran modül)
use ml::MlIf; // (ONNX isolation forest sarmalayıcısı)
use once_cell::sync::OnceCell; // (tembel/ilk kullanımda bir kere yükle)
use rules::{Thresholds as RThresh, Whitelist as RWhite, evaluate}; // (kural motoru)
use serde::{Deserialize, Serialize}; // (JSON/TOML serileştirme)
use std::{
    collections::{HashMap, HashSet}, // (bastırma/suppression için küçük bellek)
    fs::{self, OpenOptions},         // (dosyaya ekleme)
    io::{BufWriter, Write},          // (NDJSON yazımı için tampon + writeln!)
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

/// ML nesnesini tembelce bir kere yüklemek için hücre (OnceCell: bir kere set edilir)
/// (tembel yükleme = ilk ihtiyaç olduğunda yükle)
static ML: OnceCell<MlIf> = OnceCell::new();

fn ensure_ml(model_path: &str) -> anyhow::Result<&'static MlIf> {
    ML.get_or_try_init(|| MlIf::new(model_path))
}

/// === 7'li özellik vektörü (model girişi: [N,7]) ===
/// Model, ONNX TreeEnsemble için [N,F] bekler; biz F=7 üretiyoruz.
/// (domain uzunluğu, entropi, label sayısı, TXT oranı, NXDOMAIN oranı, QPS, benzersiz-alt oranı)
fn build_x7(fv: &FeatureVector) -> [f32; 7] {
    [
        fv.domain_len as f32,
        fv.shannon_entropy,
        fv.label_count as f32,
        fv.txt_ratio,
        fv.nxdomain_ratio,
        fv.qps_client,
        fv.unique_sub_ratio,
    ]
}

// --- Config şeması (demo/minimum TOML ile uyumlu) ---
#[derive(Debug, Deserialize)]
struct Config {
    thresholds: Thresholds,
    #[serde(default)]
    whitelist: Whitelist,
    #[serde(default)]
    ml: Ml,
}

// === features.ndjson satırı (isteğe bağlı ham özellik dökümü) ===
#[derive(Serialize)]
struct WindowFlat {
    txt_ratio: f32,        // (pencerede TXT oranı)
    nxerr_ratio: f32,      // (pencerede NXDOMAIN/servfail oranı)
    qps_client: f32,       // (istemci başına saniye başına sorgu)
    unique_sub_ratio: f32, // (benzersiz subdomain oranı)
}

#[derive(Serialize)]
struct FeatureRow {
    uid: u64,            // (tekil sıra no)
    ts_ns: u128,         // (epoch nanosaniye)
    client_ip: String,   // (şimdilik boş — pcap’te yoksa "")
    qname: String,       // (tam sorgu adı)
    qtype: String,       // (A/AAAA/TXT vs.)
    len: u16,            // (qname uzunluğu)
    entropy: f32,        // (Shannon entropi)
    labels: u8,          // (etiket sayısı: a.b.c → 3)
    root_domain: String, // (ör: spotify.com)
    window: WindowFlat,  // (pencere bazlı metrikler)
}

// --- Eşikler (kural tarafı) ---
// alias: eski adları da kabul et (örn. min_nxdomain_ratio/min_unique_sub_ratio)
#[derive(Debug, Deserialize)]
struct Thresholds {
    min_domain_len: usize, // (minimum alan adı uzunluğu)
    min_entropy: f32,      // (minimum entropi)
    min_txt_ratio: f32,    // (TXT ağırlığı)
    #[serde(alias = "min_nxdomain_ratio")]
    min_nx_ratio: f32, // (NXDOMAIN/SERVFAIL oranı)
    min_qps_client: f32,   // (istemci başına QPS)
    #[serde(alias = "min_unique_sub_ratio")]
    min_unique_sub: f32, // (benzersiz subdomain oranı)
}

// --- Whitelist (kök alan son ekleri; örn "spotify.com", ".arpa") ---
#[derive(Debug, Deserialize, Default)]
struct Whitelist {
    /// config’te "roots" yazsan da okunsun:
    #[serde(default, alias = "roots")]
    domains: Vec<String>,
}

// --- Çıkış hedefi (stdout / opensearch / webhook; şu an stdout ve dosya) ---
// (Sink/SinkKind kaldırıldı: kullanılmıyordu)

// --- ML ayarları ---
#[derive(Debug, Deserialize, Default)]
struct Ml {
    #[serde(default)]
    mode: MlMode, // (none/onnx/json)
    #[serde(default)]
    model_path: String, // (models/iforest.onnx)
    #[serde(default)]
    score_threshold: Option<f32>, // (IForest: skor eşik — daha negatif = daha anormal)
}

#[derive(Debug, Deserialize, Default, Clone, Copy, ValueEnum)]
#[serde(rename_all = "lowercase")]
enum MlMode {
    #[default]
    None,
    Onnx,
    Json,
}

// ---- Alert JSON (NDJSON) şeması ----
#[derive(Serialize)]
struct Alert {
    ts: u64,                    // (epoch saniye)
    mode: String,               // (batch/stream)
    score: f32,                 // (kural skoru)
    reason: &'static str,       // ← (tekil kaynak: "rules" | "ml" | "both" | "none")
    reasons: Vec<&'static str>, // (tetik nedenleri: "len>=min", "entropy>=min", "ml_iforest" vs.)

    // DNS özellikleri (raporda görünür alanlar)
    qname: String,
    root: String,
    qtype: String,
    domain_len: u16,
    entropy: f32,
    txt_ratio: f32,
    nx_ratio: f32,
    qps_client: f32,
    unique_sub_ratio: f32,

    // --- ML alanları (opsiyonel; None ise yazma) ---
    #[serde(skip_serializing_if = "Option::is_none")] // (None ise JSON’a yazma)
    ml_score: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")] // (None ise JSON’a yazma)
    ml: Option<MlMeta>,
}

#[derive(Serialize)]
struct MlMeta {
    algo: &'static str, // (örn. "iforest")
    threshold: f32,     // (eşik)
}

fn read_config(path: &PathBuf) -> Result<Config> {
    let s = fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Config okunamadı: {} ({e})", path.display()))?;
    let cfg: Config = toml::from_str(&s)?;
    Ok(cfg)
}

#[allow(clippy::too_many_arguments)]
fn make_alert_json(
    mode: &str,
    fv: &FeatureVector,
    score: f32,
    mut reasons: Vec<&'static str>,
    qname: &str,
    root: &str,
    qtype: String,
    // --- ML verileri ---
    ml_score: Option<f32>,
    ml_threshold: Option<f32>,
    ml_is_anom: bool,
    // --- tekil reason için kural hiti bilgisi ---
    rule_hit: bool,
) -> Result<String> {
    if ml_is_anom {
        reasons.push("ml_iforest"); // (ML de desteklediyse sebebe ekle)
    }

    // Tekil reason etiketi:
    let reason: &'static str = match (rule_hit, ml_is_anom) {
        (true, true) => "both",
        (true, false) => "rules",
        (false, true) => "ml",
        (false, false) => "none",
    };

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let alert = Alert {
        ts,
        mode: mode.to_string(),
        score,
        reason, // ← eklendi
        reasons,
        qname: qname.to_string(),
        qtype,
        root: root.to_string(),
        domain_len: fv.domain_len,
        entropy: fv.shannon_entropy,
        txt_ratio: fv.txt_ratio,
        nx_ratio: fv.nxdomain_ratio,
        qps_client: fv.qps_client,
        unique_sub_ratio: fv.unique_sub_ratio,
        ml_score,
        ml: ml_score.map(|_| MlMeta {
            algo: "iforest",
            threshold: ml_threshold.unwrap_or(0.0),
        }),
    };
    Ok(serde_json::to_string(&alert)?)
}

// --- Küçük yardımcılar ---
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// "a.b.c.example.com." -> "example.com" (basit eTLD+1; PSL yok — demo yeter)
fn root_domain(qname: &str) -> String {
    let s = qname.trim_end_matches('.');
    let mut it = s.rsplit('.');
    let last = it.next().unwrap_or("");
    let second = it.next().unwrap_or("");
    if second.is_empty() {
        last.to_string()
    } else {
        format!("{}.{}", second, last)
    }
}

/// Whitelist: ASCII-case-insensitive son ek eşleşmesi.
/// "foo.spotify.com" → "spotify.com"; ".arpa" girdisi tüm *.arpa'yı kapsar.
fn is_whitelisted_root(wl: &Whitelist, root: &str) -> bool {
    let r = root.trim_end_matches('.').to_ascii_lowercase();
    wl.domains.iter().any(|w| {
        let t = w.trim_matches('.').to_ascii_lowercase();
        r == t || r.ends_with(&format!(".{t}"))
    })
}

// --- Basit bastırma (suppression): aynı pencere içinde aynı (root,qtype) için tek alarm ---
struct AlertSuppressor {
    window: u64, // saniye
    buckets: HashMap<u64, HashSet<(String, String)>>,
}
impl AlertSuppressor {
    fn new(window: u64) -> Self {
        Self {
            window,
            buckets: HashMap::new(),
        }
    }
    fn should_emit(&mut self, event_ts: u64, root: &str, qtype: &str) -> bool {
        let b = event_ts / self.window;
        let set = self.buckets.entry(b).or_default();
        let inserted = set.insert((root.to_owned(), qtype.to_owned()));

        // küçük temizlik: çok eski kovaları at
        if self.buckets.len() > 6 {
            let min_keep = b.saturating_sub(3);
            self.buckets.retain(|&k, _| k >= min_keep);
        }
        inserted
    }
}

// --- CLI ---
#[derive(Clone, Copy, Debug, ValueEnum)]
enum Mode {
    Batch,
    Stream,
}

#[derive(Debug, Parser)]
#[command(
    name = "dns-detector",
    version,
    about = "PDF-min CLI (pcap analizi & olay üretimi)"
)]
struct Args {
    /// batch | stream
    #[arg(value_enum, long, default_value = "batch")]
    mode: Mode,

    /// batch kipinde pcap yolu (örn. data/dns-lab-10q.pcapng)
    #[arg(long)]
    pcap: Option<PathBuf>,

    /// stream kipinde arayüz adı (örn. eth0)
    #[arg(long)]
    iface: Option<String>,

    /// TOML config yolu
    #[arg(long, default_value = "config/minimal.toml")]
    config: PathBuf,

    /// Opsiyonel: alertleri NDJSON dosyasına ekle
    #[arg(long)]
    out: Option<PathBuf>,

    /// Opsiyonel: her DNS olayı için özellikleri NDJSON olarak yaz (--feat-out)
    #[arg(long = "feat-out")]
    feat_out: Option<PathBuf>,

    /// Aynı (root,qtype) için bastırma penceresi (saniye)
    #[arg(long, default_value_t = 60)]
    suppress_secs: u64,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // OUT dosyasını baştan oluştur (alert çıkmasa da var olsun)
    if let Some(path) = &args.out {
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
    }

    // features.ndjson writer (opsiyonel)
    let mut feat_writer = if let Some(path) = &args.feat_out {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true) // her koşuda sıfırdan başla
            .open(path)?;
        Some(BufWriter::new(file))
    } else {
        None
    };

    match args.mode {
        Mode::Batch => {
            let pcap = args.pcap.as_ref().expect("--pcap zorunlu (batch kipinde)");
            let cfg = read_config(&args.config)?;

            // Kurallar/Whitelist adaptasyonu
            let th = RThresh {
                min_domain_len: cfg.thresholds.min_domain_len as u16,
                min_entropy: cfg.thresholds.min_entropy,
                min_txt_ratio: cfg.thresholds.min_txt_ratio,
                min_nx_ratio: cfg.thresholds.min_nx_ratio,
                min_qps_client: cfg.thresholds.min_qps_client,
                min_unique_sub: cfg.thresholds.min_unique_sub,
            };
            let wl = RWhite {
                domains: cfg.whitelist.domains.clone(),
            };

            let mut reader = PcapReader::open(pcap)?; // (pcap dosyasını aç)
            let mut win = WindowState::new(60); // (60 sn pencere metrikleri)
            let mut suppressor = AlertSuppressor::new(args.suppress_secs);

            // === ana döngü ===
            while let Some(rec) = reader.next() {
                // Özellik çıkar (feature engineering)
                let fv = features::extract(&rec, &mut win);

                // mini görünür log (gözle teyit)
                println!(
                    "[dns] seen qname={} qtype={} | len={} labels={} H={:.2}",
                    rec.qname, rec.qtype, fv.domain_len, fv.label_count, fv.shannon_entropy
                );

                // Kök alanı hesapla (ör. "a.b.spotify.com" -> "spotify.com")
                let root = root_domain(&rec.qname);

                // --- features.ndjson'ı yaz (opsiyonel) ---
                if let Some(w) = feat_writer.as_mut() {
                    let now_ns = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos();

                    let row = FeatureRow {
                        uid: now_ns as u64, // (örnek sıra; istersen artan sayaçla değiştir)
                        ts_ns: now_ns,
                        client_ip: String::new(),
                        qname: rec.qname.clone(),
                        qtype: rec.qtype.to_string(),
                        len: fv.domain_len as u16,
                        entropy: fv.shannon_entropy,
                        labels: fv.label_count as u8,
                        root_domain: root.clone(),
                        window: WindowFlat {
                            txt_ratio: fv.txt_ratio,
                            nxerr_ratio: fv.nxdomain_ratio,
                            qps_client: fv.qps_client,
                            unique_sub_ratio: fv.unique_sub_ratio,
                        },
                    };

                    serde_json::to_writer(&mut *w, &row)?;
                    w.write_all(b"\n")?;
                }

                // --- ML: her kayıtta skoru hesapla ---
                let mut ml_score_opt: Option<f32> = None;
                let mut ml_is_anom = false;

                if matches!(cfg.ml.mode, MlMode::Onnx) && !cfg.ml.model_path.is_empty() {
                    match ensure_ml(&cfg.ml.model_path) {
                        Ok(m) => {
                            let x7 = build_x7(&fv);
                            match m.predict_vec(&x7) {
                                Ok(out) => {
                                    if let Some(s) = out.score {
                                        println!(
                                            "[ml] score={:.3} label={:?} qname={}",
                                            s, out.label, rec.qname
                                        );
                                        ml_score_opt = Some(s);
                                    } else {
                                        eprintln!(
                                            "[ml] uyarı: model çıktısı 'score' alanı içermiyor"
                                        );
                                    }
                                    ml_is_anom = out.is_anomaly(cfg.ml.score_threshold);
                                }
                                Err(e) => eprintln!("[ml] predict error: {e}"),
                            }
                        }
                        Err(e) => eprintln!("[ml] load error (ORT DLL veya model yolu): {e}"),
                    }
                }

                // --- WHITELIST kısa devre: kural + ML-only uyarıları tamamen kes ---
                if is_whitelisted_root(&cfg.whitelist, &root) {
                    continue;
                }

                // suppression için ortak zaman:
                let event_ts = now_secs();
                let qtype_s = rec.qtype.to_string();

                // 1) Kural tetiklenirse
                if let Some(sig) = evaluate(&fv, &wl, &th, &root) {
                    if suppressor.should_emit(event_ts, &root, &qtype_s) {
                        let line = make_alert_json(
                            "batch",
                            &fv,
                            sig.score,
                            sig.reasons.clone(),
                            &rec.qname,
                            &root,
                            qtype_s.clone(),
                            ml_score_opt,
                            cfg.ml.score_threshold,
                            ml_is_anom,
                            true, // ← rule_hit
                        )?;

                        if let Some(path) = args.out.as_ref() {
                            let mut f = OpenOptions::new().create(true).append(true).open(path)?;
                            writeln!(f, "{}", line)?;
                        } else {
                            println!("{}", line);
                        }
                    } // else: bastırıldı
                }
                // 2) Kural tetiklemediyse ama ML anomali dediyse (yalnız ML)
                else if ml_is_anom {
                    if suppressor.should_emit(event_ts, &root, &qtype_s) {
                        let line = make_alert_json(
                            "batch",
                            &fv,
                            0.0, // kural skoru yok
                            vec![],
                            &rec.qname,
                            &root,
                            qtype_s.clone(),
                            ml_score_opt,
                            cfg.ml.score_threshold,
                            ml_is_anom,
                            false, // ← rule_hit yok
                        )?;

                        if let Some(path) = args.out.as_ref() {
                            let mut f = OpenOptions::new().create(true).append(true).open(path)?;
                            writeln!(f, "{}", line)?;
                        } else {
                            println!("{}", line);
                        }
                    } // else: bastırıldı
                }
            }

            println!(
                "[OK] MODE=batch | pcap={} | config={}",
                pcap.display(),
                args.config.display()
            );
        }

        Mode::Stream => {
            // (Stream: ileride gerçek arayüzden okuma eklenecek)
            let iface = args
                .iface
                .as_deref()
                .expect("--iface zorunlu (stream kipinde)");
            let cfg = read_config(&args.config)?;
            println!("[INFO] Stream henüz demo modunda. iface={}", iface);
            println!("{:#?}", cfg);
        }
    }

    Ok(())
}

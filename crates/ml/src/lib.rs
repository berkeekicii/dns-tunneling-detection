// crates/ml/src/lib.rs
use anyhow::{Result, bail};
use std::sync::Mutex;

use ort::{
    init,
    session::{Session, builder::SessionBuilder},
    value::Tensor,
};

/// IsolationForest ONNX modeli için küçük bir çıkarım sarmalayıcı.
pub struct MlIf {
    // v2: run(&mut self) istediği için Session'ı Mutex ile tutuyoruz
    sess: Mutex<Session>,
}

/// Çıktılar: skl2onnx IF genelde `label` (Int64; -1 anomali, 1 normal)
/// ve `scores` (Float; skor küçüldükçe daha anormal) üretir.
#[derive(Debug, Clone)]
pub struct MlOut {
    pub label: Option<i64>,
    pub score: Option<f32>,
}

impl MlOut {
    /// Eşik verilmişse skora bak; yoksa label -1 mi diye kontrol et.
    pub fn is_anomaly(&self, score_threshold: Option<f32>) -> bool {
        if let Some(th) = score_threshold {
            if let Some(s) = self.score {
                return s < th;
            }
        }
        matches!(self.label, Some(-1))
    }
}

impl MlIf {
    /// Modeli dosyadan yükle (ort v2 rc10).
    pub fn new(model_path: &str) -> Result<Self> {
        // v2: Environment yerine global init (DLL yolunu load-dynamic ile buradan alır)
        init().with_name("iforest").commit()?;

        // v2: Session::builder()?.commit_from_file(...)
        let sess = SessionBuilder::new()?.commit_from_file(model_path)?;
        Ok(Self {
            sess: Mutex::new(sess),
        })
    }

    /// GENEL giriş: keyfi uzunlukta özellik vektörünü [1,F] olarak besle.
    /// TreeEnsemble* operatörleri girişte [N,F] bekler (biz N=1 veriyoruz).
    pub fn predict_vec(&self, x: &[f32]) -> Result<MlOut> {
        if x.is_empty() {
            bail!("predict_vec: empty feature vector");
        }

        // v2: allocator YOK; doğrudan (shape, data) verilir.
        let input: Tensor<f32> = Tensor::from_array(([1_usize, x.len()], x.to_vec()))?;

        // Session'a mutable erişim (run(&mut self) için)
        let mut sess = self
            .sess
            .lock()
            .map_err(|e| anyhow::anyhow!("Session mutex poisoned: {e}"))?;

        // Çalıştır
        let outputs = sess.run(ort::inputs![input])?;
        if outputs.len() == 0 {
            bail!("ml.predict_vec(): empty outputs");
        }

        // Çıktıları topla: önce skor (f32/f64), sonra label (i64)
        let mut label: Option<i64> = None;
        let mut score: Option<f32> = None;

        for (_name, val) in outputs.iter() {
            // --- score (float) ---
            if score.is_none() {
                if let Ok((_shape, data)) = val.try_extract_tensor::<f32>() {
                    if let Some(&s) = data.first() {
                        score = Some(s);
                        continue;
                    }
                }
                if let Ok((_shape, data)) = val.try_extract_tensor::<f64>() {
                    if let Some(&s) = data.first() {
                        score = Some(s as f32);
                        continue;
                    }
                }
            }

            // --- label (int64) ---
            if label.is_none() {
                if let Ok((_shape, data)) = val.try_extract_tensor::<i64>() {
                    if let Some(&l) = data.first() {
                        label = Some(l);
                        continue;
                    }
                }
            }
        }

        Ok(MlOut { label, score })
    }

    /// GERİYE UYUMLULUK: Eski 1x3 çağrıları destekler.
    /// Not: Yeni kodlar `predict_vec(&[f32])` kullanmalı.
    pub fn predict(&self, len: f32, labels: f32, entropy: f32) -> Result<MlOut> {
        self.predict_vec(&[len, labels, entropy])
    }
}

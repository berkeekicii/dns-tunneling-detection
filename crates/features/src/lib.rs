use collector::DnsRecord;
use std::time::{SystemTime, UNIX_EPOCH};

mod window;
pub use window::WindowState;

// PDF: özellikler (domain uzunluğu, alt alan sayısı, entropi, TXT/NULL oranı, QPS vs.)
#[derive(Clone, Debug, Default)]
pub struct FeatureVector {
    pub domain_len: u16,
    pub label_count: u8,
    pub shannon_entropy: f32,
    pub base64ish_ratio: f32,
    pub unique_sub_ratio: f32,
    pub txt_ratio: f32,
    pub nxdomain_ratio: f32,
    pub qps_client: f32,
}

// --- Yardımcılar ---
fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::<u8, usize>::new();
    for &b in s.as_bytes() {
        *counts.entry(b).or_insert(0) += 1;
    }
    let len = s.len() as f32;
    let mut h = 0.0f32;
    for &c in counts.values() {
        let p = (c as f32) / len;
        h -= p * (p.ln() / std::f32::consts::LN_2); // log2
    }
    h
}

// qname -> (root, sub)  ör: "a.b.c.example.com." => ("example.com", "a.b.c")
fn split_root_sub(qname: &str) -> (String, String) {
    let s = qname.trim_end_matches('.');
    let mut parts: Vec<&str> = s.split('.').filter(|p| !p.is_empty()).collect();
    if parts.len() >= 2 {
        let last = parts.pop().unwrap();
        let second = parts.pop().unwrap();
        let root = format!("{}.{}", second, last);
        let sub = if parts.is_empty() {
            String::new()
        } else {
            parts.join(".")
        };
        (root, sub)
    } else {
        (s.to_string(), String::new())
    }
}

// --- Ana çıkarım ---
pub fn extract(rec: &DnsRecord, state: &mut WindowState) -> FeatureVector {
    // Entropiyi noktalarsız alan adı üzerinde hesaplayalım
    let cleaned = rec.qname.trim_end_matches('.').replace('.', "");
    let entropy = shannon_entropy(&cleaned);

    // Pencere verilerini güncelle
    let (root, sub) = split_root_sub(&rec.qname);
    let client = if rec.client_ip.is_empty() {
        "0.0.0.0"
    } else {
        rec.client_ip.as_str()
    };
    let now_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let is_txt = rec.qtype.eq_ignore_ascii_case("TXT");
    // DNS rcode: 3 = NXDOMAIN (NameError). PcapReader şimdilik doldurmuyor; yoksa false olur.
    let is_nx = rec.rcode == Some(3);

    state.update(now_ts, client, &root, is_txt, is_nx, &sub);
    let m = state.metrics(now_ts, client, &root);

    FeatureVector {
        domain_len: rec.qname.len() as u16,
        label_count: rec.qname.split('.').filter(|s| !s.is_empty()).count() as u8,
        shannon_entropy: entropy,
        txt_ratio: m.txt_ratio,
        nxdomain_ratio: m.nxdomain_ratio,
        qps_client: m.qps_client,
        unique_sub_ratio: m.unique_sub_ratio,
        ..Default::default()
    }
}

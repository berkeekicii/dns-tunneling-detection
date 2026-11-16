use features::FeatureVector;

#[derive(Debug, Clone)]
pub struct Thresholds {
    pub min_domain_len: u16,
    pub min_entropy: f32,
    pub min_txt_ratio: f32,
    pub min_nx_ratio: f32,
    pub min_qps_client: f32,
    pub min_unique_sub: f32,
}

#[derive(Debug, Clone, Default)]
pub struct Whitelist {
    pub domains: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Signal {
    pub score: f32,
    pub reasons: Vec<&'static str>,
}

pub fn evaluate(fv: &FeatureVector, wl: &Whitelist, th: &Thresholds, root: &str) -> Option<Signal> {
    // whitelist: kök alan listedeyse uyarı üretme
    if wl.domains.iter().any(|d| d.eq_ignore_ascii_case(root)) {
        return None;
    }

    let mut score = 0.0f32;
    let mut reasons = Vec::new();

    // basit kurallar (ağırlıklar örnek; ihtiyaca göre oynayabiliriz)
    if fv.domain_len >= th.min_domain_len {
        score += 0.4;
        reasons.push("len>=min");
    }
    if fv.shannon_entropy >= th.min_entropy {
        score += 0.6;
        reasons.push("entropy>=min");
    }
    if fv.txt_ratio >= th.min_txt_ratio && th.min_txt_ratio > 0.0 {
        score += 0.3;
        reasons.push("txt_ratio>=min");
    }
    if fv.nxdomain_ratio >= th.min_nx_ratio && th.min_nx_ratio > 0.0 {
        score += 0.3;
        reasons.push("nxdomain_ratio>=min");
    }
    if fv.qps_client >= th.min_qps_client && th.min_qps_client > 0.0 {
        score += 0.3;
        reasons.push("qps>=min");
    }
    if fv.unique_sub_ratio >= th.min_unique_sub && th.min_unique_sub > 0.0 {
        score += 0.3;
        reasons.push("unique_sub>=min");
    }

    // eşiği aşarsa sinyal üret
    if score >= 1.0 {
        Some(Signal { score, reasons })
    } else {
        None
    }
}

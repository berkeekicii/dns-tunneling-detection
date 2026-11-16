use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Clone, Debug)]
struct Ev {
    ts: u64,
    is_txt: bool,
    is_nx: bool,
    sub: String,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct WindowMetrics {
    pub txt_ratio: f32,
    pub nxdomain_ratio: f32,
    pub qps_client: f32,
    pub unique_sub_ratio: f32,
}

#[derive(Debug, Default)]
pub struct WindowState {
    window_secs: u64,
    // key = (client_ip, root_domain)
    buckets: HashMap<(String, String), VecDeque<Ev>>,
}

impl WindowState {
    pub fn new(window_secs: u64) -> Self {
        Self {
            window_secs,
            buckets: HashMap::new(),
        }
    }

    pub fn update(
        &mut self,
        ts: u64,
        client_ip: &str,
        root: &str,
        is_txt: bool,
        is_nx: bool,
        sub: &str,
    ) {
        let window_secs = self.window_secs;

        let key = (client_ip.to_string(), root.to_string());
        let q = self.buckets.entry(key).or_default();
        q.push_back(Ev {
            ts,
            is_txt,
            is_nx,
            sub: sub.to_string(),
        });
        Self::purge_old(q, ts, window_secs);
    }

    pub fn metrics(&mut self, now_ts: u64, client_ip: &str, root: &str) -> WindowMetrics {
        let window_secs = self.window_secs;
        let key = (client_ip.to_string(), root.to_string());
        let q = self.buckets.entry(key).or_default();
        Self::purge_old(q, now_ts, window_secs);

        let total = q.len() as f32;
        if total == 0.0 {
            return WindowMetrics::default();
        }

        let txt = q.iter().filter(|e| e.is_txt).count() as f32;
        let nx = q.iter().filter(|e| e.is_nx).count() as f32;

        let mut uniq: HashSet<&str> = HashSet::new();
        for e in q.iter() {
            uniq.insert(&e.sub);
        }
        let uniq_cnt = uniq.len() as f32;

        WindowMetrics {
            txt_ratio: txt / total,
            nxdomain_ratio: nx / total,
            qps_client: total / (window_secs as f32),
            unique_sub_ratio: (uniq_cnt / total).min(1.0),
        }
    }

    fn purge_old(q: &mut VecDeque<Ev>, now_ts: u64, window_secs: u64) {
        let cutoff = now_ts.saturating_sub(window_secs);
        while let Some(front) = q.front() {
            if front.ts < cutoff {
                q.pop_front();
            } else {
                break;
            }
        }
    }
}

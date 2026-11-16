// src/lib.rs
use anyhow::Result;
use dns_parser::Packet;
use pcap::Capture;

#[derive(Clone, Debug)]
pub struct DnsRecord {
    pub ts_ms: u128,       // zaman damgası (ms)
    pub client_ip: String, // kaynak IP
    pub qname: String,     // sorgu adı
    pub qtype: String,     // A/AAAA/TXT/CNAME/NULL
    pub ttl: Option<u32>,
    pub rcode: Option<u16>, // NOERROR/NXDOMAIN vb.
    pub size: u16,          // paket boyutu
}

pub trait PacketSource {
    fn next(&mut self) -> Option<DnsRecord>;
}

pub struct PcapReader {
    cap: Capture<pcap::Offline>,
}

// Batch: pcap okuyucu (artık gerçek pcap okuyacak)

impl PcapReader {
    pub fn open(path: &std::path::Path) -> Result<Self> {
        // pcap dosyasını açıp yalnızca UDP/53 paketlerini geçir
        let mut cap = Capture::from_file(path)?;
        cap.filter("udp port 53", true)?;
        Ok(Self { cap })
    }
}

impl PacketSource for PcapReader {
    fn next(&mut self) -> Option<DnsRecord> {
        match self.cap.next_packet() {
            Ok(pkt) => {
                let data = pkt.data;
                // En az Ethernet + IPv4 + UDP başlığı kadar veri var mı?
                if data.len() < 42 {
                    return None;
                }
                // DNS verisi UDP başlığından sonra başlar
                let dns_data = &data[42..];
                if let Ok(parsed) = Packet::parse(dns_data) {
                    if let Some(question) = parsed.questions.first() {
                        // Basit bir DnsRecord dolduralım
                        return Some(DnsRecord {
                            ts_ms: 0,                 // şimdilik 0, ileride timestamp ekleriz
                            client_ip: String::new(), // ileride IP parse edilecek
                            qname: question.qname.to_string(),
                            qtype: format!("{:?}", question.qtype),
                            ttl: None,
                            rcode: None,
                            size: pkt.header.len as u16,
                        });
                    }
                }
                None
            }
            Err(_) => None, // Okunacak paket kalmadı
        }
    }
}

use tokio::net::UdpSocket;
use std::sync::Arc;
use std::time::Duration;

// Configuration
const CLOCK_IDS_PORT: u16 = 8001;
const ETH_MONITOR_ADDR: &str = "127.0.0.1:8002";
const TIME_WINDOW_NS: u64 = 50_000_000; // 50ms window before and after anomaly

#[derive(Debug)]
struct CanAnomaly {
    can_id: u32,
    gptp_ts: u64,
    skew: f64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("[CentralProcessor] Starting on ARM Architecture...");
    
    // Bind socket to listen for ClockIDS anomalies
    let socket = UdpSocket::bind(format!("0.0.0.0:{}", CLOCK_IDS_PORT)).await?;
    let socket = Arc::new(socket);
    
    println!("[CentralProcessor] Listening for CAN anomalies on port {}...", CLOCK_IDS_PORT);

    let mut buf = [0u8; 1024];

    loop {
        let (len, _addr) = socket.recv_from(&mut buf).await?;
        
        if len >= 21 && buf[0] == 0x01 {
            // Parse CAN Anomaly
            let mut can_id_bytes = [0u8; 4];
            can_id_bytes.copy_from_slice(&buf[1..5]);
            let can_id = u32::from_ne_bytes(can_id_bytes);

            let mut ts_bytes = [0u8; 8];
            ts_bytes.copy_from_slice(&buf[5..13]);
            let gptp_ts = u64::from_ne_bytes(ts_bytes);

            let mut skew_bytes = [0u8; 8];
            skew_bytes.copy_from_slice(&buf[13..21]);
            let skew = f64::from_ne_bytes(skew_bytes);

            let anomaly = CanAnomaly { can_id, gptp_ts, skew };
            println!("\n[CentralProcessor] Received Anomaly: {:?}", anomaly);

            // Trigger Ethernet Data Request
            request_ethernet_data(gptp_ts, socket.clone()).await?;
        }
    }
}

async fn request_ethernet_data(anomaly_ts: u64, socket: Arc<UdpSocket>) -> Result<(), Box<dyn std::error::Error>> {
    let start_ts = anomaly_ts.saturating_sub(TIME_WINDOW_NS);
    let end_ts = anomaly_ts.saturating_add(TIME_WINDOW_NS);

    println!("[CentralProcessor] Requesting Ethernet data for window: {} to {}", start_ts, end_ts);

    let mut req_buf = Vec::new();
    req_buf.extend_from_slice(&start_ts.to_ne_bytes());
    req_buf.extend_from_slice(&end_ts.to_ne_bytes());

    // Send request to Ethernet Monitor
    socket.send_to(&req_buf, ETH_MONITOR_ADDR).await?;

    // Wait for response
    let mut resp_buf = [0u8; 1024];
    let timeout = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut resp_buf)).await;

    match timeout {
        Ok(Ok((len, _))) => {
            if len >= 4 {
                let mut count_bytes = [0u8; 4];
                count_bytes.copy_from_slice(&resp_buf[0..4]);
                let count = u32::from_ne_bytes(count_bytes);
                
                println!("[CentralProcessor] Received {} Ethernet packets for analysis.", count);
                
                // Trigger ML Analysis
                run_ml_analysis(anomaly_ts, count).await;
            }
        }
        _ => {
            println!("[CentralProcessor] Timeout waiting for Ethernet Monitor response.");
        }
    }

    Ok(())
}

async fn run_ml_analysis(anomaly_ts: u64, eth_packet_count: u32) {
    println!("[CentralProcessor] --- ML Analysis Started ---");
    println!("[CentralProcessor] Correlating CAN anomaly at {} with {} Ethernet packets...", anomaly_ts, eth_packet_count);
    
    // Placeholder for actual ML inference (e.g., using linfa or tract for ONNX models on ARM)
    // The ML model would look for temporal correlations (e.g., a DoIP diagnostic request 
    // immediately preceding the CAN masquerade attack).
    
    tokio::time::sleep(Duration::from_millis(500)).await; // Simulate processing time
    
    println!("[CentralProcessor] --- ML Analysis Complete ---");
    println!("[CentralProcessor] >> ATTACK CHAIN IDENTIFIED <<");
    println!("[CentralProcessor] 1. Malicious DoIP payload received via Ethernet (OBD-II port).");
    println!("[CentralProcessor] 2. Gateway compromised, routing unauthorized diagnostic frames to CAN.");
    println!("[CentralProcessor] 3. Clock Skew detected on CAN ID 0x123 (Masquerade Attack).");
    println!("[CentralProcessor] Action: Isolating Ethernet port and dropping CAN ID 0x123.");
}

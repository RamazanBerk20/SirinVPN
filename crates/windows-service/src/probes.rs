//! Bounded native ICMP probes use the private tunnel source and VPS address.
//! Request payloads contain random padding, never application traffic or secrets.
use sirinvpn_protocol::{TransportKind, TransportQualitySample};
use std::{io, net::Ipv4Addr, ptr, time::Duration};
use windows_sys::Win32::{
    Foundation::{HANDLE, INVALID_HANDLE_VALUE},
    NetworkManagement::IpHelper::*,
    System::IO::IO_STATUS_BLOCK,
};

pub(crate) async fn ping(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    payload: u16,
    timeout_ms: u32,
) -> Option<u32> {
    struct Task(tokio::task::JoinHandle<io::Result<u32>>);
    impl Drop for Task {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let mut task = Task(tokio::task::spawn_blocking(move || {
        echo(source, destination, payload, timeout_ms)
    }));
    (&mut task.0).await.ok()?.ok()
}

pub(crate) async fn sample(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    transport: TransportKind,
) -> Option<TransportQualitySample> {
    let mut values = Vec::with_capacity(8);
    for _ in 0..8 {
        if let Some(micros) = ping(source, destination, 32, 350).await {
            values.push(micros);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    if values.is_empty() {
        return None;
    }
    let latency = values.iter().map(|value| u64::from(*value)).sum::<u64>() / values.len() as u64;
    // Mean absolute change between consecutive replies, kept in RAM only.
    let jitter = values
        .windows(2)
        .map(|pair| u64::from(pair[0].abs_diff(pair[1])))
        .sum::<u64>()
        / values.len().saturating_sub(1).max(1) as u64;
    let sample = TransportQualitySample {
        transport,
        probes_sent: 8,
        probes_received: values.len() as u8,
        latency_micros: latency as u32,
        jitter_micros: jitter as u32,
    };
    sample.valid().then_some(sample)
}

fn echo(source: Ipv4Addr, destination: Ipv4Addr, payload: u16, timeout_ms: u32) -> io::Result<u32> {
    if source.octets()[..3] != [10, 77, 0]
        || destination != Ipv4Addr::new(10, 77, 0, 1)
        || !(16..=1392).contains(&payload)
        || !(1..=1000).contains(&timeout_ms)
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let handle = unsafe { IcmpCreateFile() };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    struct Icmp(HANDLE);
    impl Drop for Icmp {
        fn drop(&mut self) {
            unsafe {
                IcmpCloseHandle(self.0);
            }
        }
    }
    let _icmp = Icmp(handle);
    let nonce = uuid::Uuid::new_v4();
    let data = (0..usize::from(payload))
        .map(|index| nonce.as_bytes()[index % 16])
        .collect::<Vec<_>>();
    let size = size_of::<ICMP_ECHO_REPLY>() + data.len() + 8 + size_of::<IO_STATUS_BLOCK>();
    let mut reply = vec![0u64; size.div_ceil(8)];
    let options = IP_OPTION_INFORMATION {
        Ttl: 64,
        Tos: 0,
        Flags: IP_FLAG_DF as u8,
        OptionsSize: 0,
        OptionsData: ptr::null_mut(),
    };
    let count = unsafe {
        IcmpSendEcho2Ex(
            handle,
            ptr::null_mut(),
            None,
            ptr::null(),
            u32::from_ne_bytes(source.octets()),
            u32::from_ne_bytes(destination.octets()),
            data.as_ptr().cast(),
            payload,
            &options,
            reply.as_mut_ptr().cast(),
            size as u32,
            timeout_ms,
        )
    };
    if count == 0 {
        return Err(io::Error::last_os_error());
    }
    let result = unsafe { &*reply.as_ptr().cast::<ICMP_ECHO_REPLY>() };
    if result.Status != IP_SUCCESS
        || result.Address != u32::from_ne_bytes(destination.octets())
        || result.DataSize != payload
        || result.Data.is_null()
        || result.RoundTripTime > 3000
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let begin = reply.as_ptr() as usize;
    let end = begin + size;
    let address = result.Data as usize;
    if address < begin
        || address
            .checked_add(data.len())
            .is_none_or(|end_of_data| end_of_data > end)
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let received = unsafe { std::slice::from_raw_parts(result.Data.cast::<u8>(), data.len()) };
    if received != data {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(result.RoundTripTime * 1000)
}

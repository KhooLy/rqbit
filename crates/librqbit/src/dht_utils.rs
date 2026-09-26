use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::Context;
use buffers::ByteBufOwned;
use futures::{Stream, StreamExt, stream::FuturesUnordered};
use librqbit_core::torrent_metainfo::TorrentMetaV1Info;
use tracing::{Instrument, debug, debug_span};

use crate::{
    peer_connection::PeerConnectionOptions, peer_info_reader, spawn_utils::BlockingSpawner,
    stream_connect::StreamConnector,
};
use librqbit_core::hash_id::Id20;

const FIRST_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const RETRY_BACKOFF: [Duration; 3] = [
    Duration::ZERO,
    Duration::from_secs(5),
    Duration::from_secs(15),
];

#[derive(Debug, Default)]
pub struct MagnetResolveProgress {
    seen: AtomicU64,
    connecting: AtomicU64,
    failed: AtomicU64,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct MagnetResolveSnapshot {
    pub seen: u64,
    pub connecting: u64,
    pub failed: u64,
}

impl MagnetResolveProgress {
    pub fn snapshot(&self) -> MagnetResolveSnapshot {
        MagnetResolveSnapshot {
            seen: self.seen.load(Ordering::Relaxed),
            connecting: self.connecting.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ReadMetainfoResult<Rx> {
    Found {
        info: TorrentMetaV1Info<ByteBufOwned>,
        info_bytes: ByteBufOwned,
        rx: Rx,
        seen: HashSet<SocketAddr>,
        source: SocketAddr,
        failed: HashSet<SocketAddr>,
    },
    ChannelClosed {
        #[allow(dead_code)]
        seen: HashSet<SocketAddr>,
    },
}

pub async fn read_metainfo_from_peer_receiver<A: Stream<Item = SocketAddr> + Unpin>(
    peer_id: Id20,
    info_hash: Id20,
    initial_addrs: Vec<SocketAddr>,
    addrs_stream: A,
    peer_connection_options: Option<PeerConnectionOptions>,
    connector: Arc<StreamConnector>,
    client_name_and_version: String,
    progress: &MagnetResolveProgress,
) -> ReadMetainfoResult<A> {
    let mut seen = HashSet::<SocketAddr>::new();
    let mut failed = HashSet::<SocketAddr>::new();
    let mut addrs = addrs_stream;

    let read_info_guarded = |addr| {
        let connector = connector.clone();
        let client_name_and_version = client_name_and_version.clone();
        progress.seen.fetch_add(1, Ordering::Relaxed);
        async move {
            let mut ret = Err(anyhow::anyhow!("not attempted"));
            for (attempt, backoff) in RETRY_BACKOFF.into_iter().enumerate() {
                tokio::time::sleep(backoff).await;
                progress.connecting.fetch_add(1, Ordering::Relaxed);
                let mut opts = peer_connection_options.unwrap_or_default();
                if attempt == 0 {
                    opts.connect_timeout = Some(
                        opts.connect_timeout
                            .map_or(FIRST_CONNECT_TIMEOUT, |t| t.min(FIRST_CONNECT_TIMEOUT)),
                    );
                }
                ret = peer_info_reader::read_metainfo_from_peer(
                    addr,
                    peer_id,
                    info_hash,
                    Some(opts),
                    // This shouldn't be called anyway as we aren't reading/writing to disk, so it's
                    // ok not to use a shared one.
                    BlockingSpawner::new(1),
                    connector.clone(),
                    client_name_and_version.clone(),
                )
                .instrument(debug_span!("read_metainfo_from_peer", ?addr))
                .await
                .with_context(|| format!("error reading metainfo from {addr}"));
                progress.connecting.fetch_sub(1, Ordering::Relaxed);
                if ret.is_ok() {
                    break;
                }
            }
            if ret.is_err() {
                progress.failed.fetch_add(1, Ordering::Relaxed);
            }
            (addr, ret)
        }
    };

    let mut unordered = FuturesUnordered::new();

    for a in initial_addrs {
        seen.insert(a);
        unordered.push(read_info_guarded(a));
    }

    let mut addrs_completed = false;

    loop {
        if addrs_completed && unordered.is_empty() {
            return ReadMetainfoResult::ChannelClosed { seen };
        }

        tokio::select! {
            done = unordered.next(), if !unordered.is_empty() => {
                match done {
                    Some((source, Ok((info, info_bytes)))) => return ReadMetainfoResult::Found { info, info_bytes, seen, rx: addrs, source, failed },
                    Some((addr, Err(e))) => {
                        debug!("{:#}", e);
                        failed.insert(addr);
                    },
                    None => unreachable!()
                }
            }

            next_addr = addrs.next(), if !addrs_completed => {
                match next_addr {
                    Some(addr) => {
                        if seen.insert(addr) {
                            unordered.push(read_info_guarded(addr));
                        }
                        continue;
                    },
                    None => {
                        addrs_completed = true;
                    },
                }
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use dht::{DhtBuilder, Id20};
    use librqbit_core::peer_id::generate_peer_id;

    use super::*;
    use std::{
        str::FromStr,
        sync::{Arc, Once},
    };

    static LOG_INIT: Once = Once::new();

    fn init_logging() {
        #[allow(unused_must_use)]
        LOG_INIT.call_once(|| {
            // pretty_env_logger::try_init();
        })
    }

    #[tokio::test]
    #[ignore]
    async fn read_metainfo_from_dht() {
        init_logging();

        let info_hash = Id20::from_str("cab507494d02ebb1178b38f2e9d7be299c86b862").unwrap();
        let dht = DhtBuilder::new().await.unwrap();

        let peer_rx = dht.get_peers(info_hash, None);
        let peer_id = generate_peer_id(b"-xx1234-");
        match read_metainfo_from_peer_receiver(
            peer_id,
            info_hash,
            Vec::new(),
            peer_rx,
            None,
            Arc::new(StreamConnector::new(Default::default()).await.unwrap()),
            crate::client_name_and_version().to_owned(),
            &Default::default(),
        )
        .await
        {
            ReadMetainfoResult::Found { info, .. } => dbg!(info),
            ReadMetainfoResult::ChannelClosed { .. } => todo!("should not have happened"),
        };
    }
}

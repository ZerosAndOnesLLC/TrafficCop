use dashmap::DashMap;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use parking_lot::Mutex;
use std::time::{Duration, Instant};

pub struct ConnectionPool {
    pools: DashMap<String, PooledClient>,
    max_idle_per_host: usize,
    idle_timeout: Duration,
}

struct PooledClient {
    client: Client<HttpConnector, http_body_util::Full<bytes::Bytes>>,
    last_used: Mutex<Instant>,
}

impl ConnectionPool {
    pub fn new(max_idle_per_host: usize, idle_timeout: Duration) -> Self {
        Self {
            pools: DashMap::new(),
            max_idle_per_host,
            idle_timeout,
        }
    }

    pub fn get_client(
        &self,
        backend_url: &str,
    ) -> Client<HttpConnector, http_body_util::Full<bytes::Bytes>> {
        if let Some(pooled) = self.pools.get(backend_url) {
            *pooled.last_used.lock() = Instant::now();
            return pooled.client.clone();
        }

        let connector = HttpConnector::new();
        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(self.idle_timeout)
            .pool_max_idle_per_host(self.max_idle_per_host)
            .build(connector);

        self.pools.insert(
            backend_url.to_string(),
            PooledClient {
                client: client.clone(),
                last_used: Mutex::new(Instant::now()),
            },
        );

        client
    }

    pub fn cleanup_idle(&self) {
        let now = Instant::now();
        self.pools.retain(|_, pooled| {
            let last_used = *pooled.last_used.lock();
            now.duration_since(last_used) < self.idle_timeout * 2
        });
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new(100, Duration::from_secs(90))
    }
}

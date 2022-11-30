//! Electrum Client

use async_trait::async_trait;
use futures::lock::Mutex;
use log::{info, warn};

use bitcoin::{Script, Txid};

use crate::async_api::AsyncElectrumApi;
use crate::async_raw_client::*;
use crate::batch::Batch;
use crate::config::Config;
use crate::types::*;
use std::convert::TryFrom;

/// Generalized Electrum client that supports multiple backends. This wraps
/// [`RawClient`](client/struct.RawClient.html) and provides a more user-friendly
/// constructor that can choose the right backend based on the url prefix.
///
/// **This is available only with the `default` features, or if `proxy` and one ssl implementation are enabled**
pub enum AsyncClientType {
    #[allow(missing_docs)]
    TCP(AsyncRawClient<ElectrumPlaintextStream>),
}

/// Generalized Electrum client that supports multiple backends. Can re-instantiate client_type if connections
/// drops
pub struct AsyncClient {
    client_type: Mutex<AsyncClientType>,
    config: Config,
    url: String,
}

macro_rules! impl_inner_call {
    ( $self:expr, $name:ident $(, $args:expr)* ) => {
    {
        let mut errors = vec![];
        loop {
            let read_client = $self.client_type.lock().await;
            let res = match &*read_client {
                AsyncClientType::TCP(inner) => inner.$name( $($args, )* ).await,
            };
            drop(read_client);
            match res {
                Ok(val) => return Ok(val),
                Err(Error::Protocol(_)) => {
                    return res;
                },
                Err(e) => {
                    let failed_attempts = errors.len() + 1;

                    if retries_exhausted(failed_attempts, $self.config.retry()) {
                        warn!("call '{}' failed after {} attempts", stringify!($name), failed_attempts);
                        return Err(Error::AllAttemptsErrored(errors));
                    }

                    warn!("call '{}' failed with {}, retry: {}/{}", stringify!($name), e, failed_attempts, $self.config.retry());

                    errors.push(e);

                    // Only one thread will try to recreate the client getting the write lock,
                    // other eventual threads will get Err and will block at the beginning of
                    // previous loop when trying to read()
                    if let Some(mut write_client) = $self.client_type.try_lock() {
                        loop {
                            std::thread::sleep(std::time::Duration::from_secs((1 << errors.len()).min(30) as u64));
                            match AsyncClientType::from_config(&$self.url, &$self.config).await {
                                Ok(new_client) => {
                                    info!("Succesfully created new client");
                                    *write_client = new_client;
                                    break;
                                },
                                Err(e) => {
                                    let failed_attempts = errors.len() + 1;

                                    if retries_exhausted(failed_attempts, $self.config.retry()) {
                                        warn!("re-creating client failed after {} attempts", failed_attempts);
                                        return Err(Error::AllAttemptsErrored(errors));
                                    }

                                    warn!("re-creating client failed with {}, retry: {}/{}", e, failed_attempts, $self.config.retry());

                                    errors.push(e);
                                }
                            }
                        }
                    }
                },
            }
        }}
    }
}

fn retries_exhausted(failed_attempts: usize, configured_retries: u8) -> bool {
    match u8::try_from(failed_attempts) {
        Ok(failed_attempts) => failed_attempts > configured_retries,
        Err(_) => true, // if the usize doesn't fit into a u8, we definitely exhausted our retries
    }
}

impl AsyncClientType {
    /// Constructor that supports multiple backends and allows configuration through
    /// the [Config]
    pub async fn from_config(url: &str, _config: &Config) -> Result<Self, Error> {
        let url = url.replacen("tcp://", "", 1);

        Ok(AsyncClientType::TCP(
            AsyncRawClient::new(url.as_str()).await?,
        ))
    }
}

impl AsyncClient {
    /// Default constructor supporting multiple backends by providing a prefix
    ///
    /// Supported prefixes are:
    /// - tcp:// for a TCP plaintext client.
    /// - ssl:// for an SSL-encrypted client. The server certificate will be verified.
    ///
    /// If no prefix is specified, then `tcp://` is assumed.
    ///
    /// See [Client::from_config] for more configuration options
    ///
    pub async fn new(url: &str) -> Result<Self, Error> {
        Self::from_config(url, Config::default()).await
    }

    /// Generic constructor that supports multiple backends and allows configuration through
    /// the [Config]
    pub async fn from_config(url: &str, config: Config) -> Result<Self, Error> {
        let client_type = Mutex::new(AsyncClientType::from_config(url, &config).await?);

        Ok(AsyncClient {
            client_type,
            config,
            url: url.to_string(),
        })
    }
}

#[async_trait]
impl AsyncElectrumApi for AsyncClient {
    #[inline]
    async fn raw_call(
        &self,
        method_name: &str,
        params: Vec<Param>,
    ) -> Result<serde_json::Value, Error> {
        // We can't passthrough this method to the inner client because it would require the
        // `params` argument to also be `Copy` (because it's used multiple times for multiple
        // retries). To avoid adding this extra trait bound we instead re-direct this call to the internal
        // `RawClient::internal_raw_call_with_vec` method.

        let vec = params.into_iter().collect::<Vec<Param>>();
        impl_inner_call!(self, internal_raw_call_with_vec, method_name, vec.clone());
    }

    #[inline]
    async fn batch_call(&self, batch: &Batch) -> Result<Vec<serde_json::Value>, Error> {
        impl_inner_call!(self, batch_call, batch)
    }

    #[inline]
    async fn block_headers_subscribe_raw(&self) -> Result<RawHeaderNotification, Error> {
        impl_inner_call!(self, block_headers_subscribe_raw)
    }

    #[inline]
    async fn block_headers_pop_raw(&self) -> Result<Option<RawHeaderNotification>, Error> {
        impl_inner_call!(self, block_headers_pop_raw)
    }

    #[inline]
    async fn block_header_raw(&self, height: usize) -> Result<Vec<u8>, Error> {
        impl_inner_call!(self, block_header_raw, height)
    }

    #[inline]
    async fn block_headers(
        &self,
        start_height: usize,
        count: usize,
    ) -> Result<GetHeadersRes, Error> {
        impl_inner_call!(self, block_headers, start_height, count)
    }

    #[inline]
    async fn estimate_fee(&self, number: usize) -> Result<f64, Error> {
        impl_inner_call!(self, estimate_fee, number)
    }

    #[inline]
    async fn relay_fee(&self) -> Result<f64, Error> {
        impl_inner_call!(self, relay_fee)
    }

    #[inline]
    async fn script_subscribe(&self, script: &Script) -> Result<Option<ScriptStatus>, Error> {
        impl_inner_call!(self, script_subscribe, script)
    }

    #[inline]
    async fn script_unsubscribe(&self, script: &Script) -> Result<bool, Error> {
        impl_inner_call!(self, script_unsubscribe, script)
    }

    #[inline]
    async fn script_pop(&self, script: &Script) -> Result<Option<ScriptStatus>, Error> {
        impl_inner_call!(self, script_pop, script)
    }

    #[inline]
    async fn script_get_balance(&self, script: &Script) -> Result<GetBalanceRes, Error> {
        impl_inner_call!(self, script_get_balance, script)
    }

    #[inline]
    async fn batch_script_get_balance(
        &self,
        scripts: Vec<Script>,
    ) -> Result<Vec<GetBalanceRes>, Error> {
        impl_inner_call!(self, batch_script_get_balance, scripts.clone())
    }

    #[inline]
    async fn script_get_history(&self, script: &Script) -> Result<Vec<GetHistoryRes>, Error> {
        impl_inner_call!(self, script_get_history, script)
    }

    #[inline]
    async fn batch_script_get_history(
        &self,
        scripts: Vec<Script>,
    ) -> Result<Vec<Vec<GetHistoryRes>>, Error> {
        impl_inner_call!(self, batch_script_get_history, scripts.clone())
    }

    #[inline]
    async fn script_list_unspent(&self, script: &Script) -> Result<Vec<ListUnspentRes>, Error> {
        impl_inner_call!(self, script_list_unspent, script)
    }

    #[inline]
    async fn batch_script_list_unspent(
        &self,
        scripts: Vec<Script>,
    ) -> Result<Vec<Vec<ListUnspentRes>>, Error> {
        impl_inner_call!(self, batch_script_list_unspent, scripts.clone())
    }

    #[inline]
    async fn transaction_get_raw(&self, txid: &Txid) -> Result<Vec<u8>, Error> {
        impl_inner_call!(self, transaction_get_raw, txid)
    }

    #[inline]
    async fn batch_transaction_get_raw(&self, txids: Vec<Txid>) -> Result<Vec<Vec<u8>>, Error> {
        impl_inner_call!(self, batch_transaction_get_raw, txids.clone())
    }

    #[inline]
    async fn transaction_get_height(&self, txid: &Txid) -> Result<Option<usize>, Error> {
        impl_inner_call!(self, transaction_get_height, txid)
    }

    #[inline]
    async fn batch_transaction_get_height(
        &self,
        txids: Vec<Txid>,
    ) -> Result<Vec<Option<usize>>, Error> {
        impl_inner_call!(self, batch_transaction_get_height, txids.clone())
    }

    #[inline]
    async fn batch_block_header_raw(&self, heights: Vec<u32>) -> Result<Vec<Vec<u8>>, Error> {
        impl_inner_call!(self, batch_block_header_raw, heights.clone())
    }

    #[inline]
    async fn batch_estimate_fee(&self, numbers: Vec<usize>) -> Result<Vec<f64>, Error> {
        impl_inner_call!(self, batch_estimate_fee, numbers.clone())
    }

    #[inline]
    async fn transaction_broadcast_raw(&self, raw_tx: &[u8]) -> Result<Txid, Error> {
        impl_inner_call!(self, transaction_broadcast_raw, raw_tx)
    }

    #[inline]
    async fn transaction_get_merkle(
        &self,
        txid: &Txid,
        height: usize,
    ) -> Result<GetMerkleRes, Error> {
        impl_inner_call!(self, transaction_get_merkle, txid, height)
    }

    #[inline]
    async fn server_features(&self) -> Result<ServerFeaturesRes, Error> {
        impl_inner_call!(self, server_features)
    }

    #[inline]
    async fn ping(&self) -> Result<(), Error> {
        impl_inner_call!(self, ping)
    }

    #[inline]
    #[cfg(feature = "debug-calls")]
    async fn calls_made(&self) -> Result<usize, Error> {
        impl_inner_call!(self, calls_made)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn test_local_timeout() {
        // This test assumes a couple things:
        // - that `localhost` is resolved to two IP addresses, `127.0.0.1` and `::1` (with the v6
        //   one having higher priority)
        // - that the system silently drops packets to `[::1]:60000` or a different port if
        //   specified through `TEST_ELECTRUM_TIMEOUT_PORT`
        //
        //   this can be setup with: ip6tables -I INPUT 1 -p tcp -d ::1 --dport 60000 -j DROP
        //   and removed with:       ip6tables -D INPUT -p tcp -d ::1 --dport 60000 -j DROP
        //
        // The test tries to create a client to `localhost` and expects it to succeed, but only
        // after at least 2 seconds have passed which is roughly the timeout time for the first
        // try.

        use std::net::TcpListener;
        use std::sync::mpsc::channel;
        use std::time::{Duration, Instant};

        let endpoint =
            std::env::var("TEST_ELECTRUM_TIMEOUT_PORT").unwrap_or("localhost:60000".into());
        let (sender, receiver) = channel();

        std::thread::spawn(move || {
            let listener = TcpListener::bind("127.0.0.1:60000").unwrap();
            sender.send(()).unwrap();

            for _stream in listener.incoming() {
                loop {}
            }
        });

        receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("Can't start local listener");

        let now = Instant::now();
        let client = AsyncClient::from_config(
            &endpoint,
            crate::config::ConfigBuilder::new().timeout(Some(5)).build(),
        )
        .await;
        let elapsed = now.elapsed();

        assert!(client.is_ok());
        assert!(elapsed > Duration::from_secs(2));
    }
}

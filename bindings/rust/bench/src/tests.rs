use crate::{
    harness::{self, TlsBenchConfig}, s2n_tls::S2NConfig, CryptoConfig, HandshakeType, Mode, OpenSslConnection, S2NConnection, SigType, TlsConnPair
};

mod fragmentation;
mod record_padding;

trait TestUtils {
    /// Assert that application data can be successfully transmitted between
    /// clients and servers.
    ///
    /// Precondition: The connections must be ready to send data (have already
    /// handshaked)
    ///
    /// 1. client sends `data_len` bytes to server
    /// 2. server reads `data_len` bytes from client
    /// 3. **ASSERT DATA EQUAL**
    /// 4. server sends `data_len` bytes to client
    /// 5. client reads `data_len` bytes from server
    /// 6. **ASSERT DATA EQUAL**
    fn round_trip_assert(&mut self, data_len: usize) -> Result<(), Box<dyn std::error::Error>>;
}

impl<C, S> TestUtils for TlsConnPair<C, S>
where
    C: harness::TlsConnIo,
    S: harness::TlsConnIo,
{
    fn round_trip_assert(&mut self, data_len: usize) -> Result<(), Box<dyn std::error::Error>> {
        let random_data = vec![0; data_len];
        let mut received_data = vec![0; data_len];

        self.client.send(&random_data)?;
        self.server.recv(&mut received_data)?;

        if !random_data.eq(&received_data) {
            return Err("data received by server does not match expected".into());
        }

        self.server.send(&random_data)?;
        self.client.recv(&mut received_data)?;

        if !random_data.eq(&received_data) {
            return Err("data received by client does not match expected".into());
        }
        Ok(())
    }
}

struct ConfigPair<C, S>(C, S);

// new_client_config()

impl<C, S> Default for ConfigPair<C, S>
where
    C: TlsBenchConfig,
    S: TlsBenchConfig,
{
    fn default() -> Self {
        // select certificate
        let crypto_config = CryptoConfig::default();

        let c = C::make_config(Mode::Client, crypto_config, HandshakeType::ServerAuth).unwrap();
        let s = S::make_config(Mode::Server, crypto_config, HandshakeType::ServerAuth).unwrap();

        // select protocol versions

        // select ciphers
        // select kx groups
        // select signatures

        //let s2n_config = s2n_tls::config::Config::builder()
        // configure with certificates

        // default configuration -> set protocol, sig scheme, ciphers, etc
        // configure certs -> mode dependent. Maybe add to trust store, maybe prepare to send

        Self(c, s)
    }
}

impl<C, S> ConfigPair<C, S> {
    pub fn split(self) -> (C, S) {
        (self.0, self.1)
    }
}

fn random_test_data(data_len: usize) -> Vec<u8> {
    let random_data = vec![0; data_len];
    // fill with random data
    random_data
}

// fn config_pair<ClientConfig, ServerConfig>()
// impl<C, S> TestUtils for TlsConnPair<C, S> {
//     fn round_trip(&mut self, data_len: usize) -> Result<(), Box<dyn std::error::Error>> {
//         todo!()
//     }
// }


#[test]
fn type_erasure() {
    let (ossl_config, s2n_config) =
    ConfigPair::<crate::openssl::OpenSslConfig, S2NConfig>::default().split();

    let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> =
        TlsConnPair::from_configs(&ossl_config, &s2n_config);

    // type erase the conn pair, which will make it easy to return in different scenarios


    assert!(pair.handshake().is_ok());
    assert!(pair.round_trip_assert(16_000).is_ok());
}

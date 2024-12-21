use async_pkey_offload::{create_self_signed_cert, get_key, KmsAsymmetricKey, DEMO_DOMAIN, DEMO_REGION};
use aws_config::{BehaviorVersion, Region};
use aws_sdk_kms::Client;
use s2n_tls::security;
use s2n_tls_tokio::{TlsAcceptor, TlsConnector};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

const MESSAGE: &[u8] = b"hello world";

// we need multiple threads, because block_on can only be used in multi-threaded
// runtimes
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake() -> Result<(), Box<dyn std::error::Error>> {
    let kms_key = {
        let shared_config = aws_config::defaults(BehaviorVersion::v2024_03_28())
            .region(Region::from_static(DEMO_REGION))
            .load()
            .await;
        let kms_client = Client::new(&shared_config);
        let key_id = get_key(&kms_client).await?;
        println!("Using KMS Key: {:?}", key_id);
        KmsAsymmetricKey::new(kms_client.clone(), key_id)
            .await
            .unwrap()
    };

    let self_signed_cert = create_self_signed_cert(kms_key.clone())?;
    // async blocks are marked `move`, so we need another copy
    let cert_copy = self_signed_cert.clone();

    // Bind to an address and listen for connections.
    // ":0" can be used to automatically assign a port.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener
        .local_addr()
        .map(|x| x.to_string())
        .unwrap_or_else(|_| "UNKNOWN".to_owned());

    let server_loop: JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>> = tokio::spawn(async move {
        let mut server_config = s2n_tls::config::Config::builder();
        server_config.set_security_policy(&security::DEFAULT_TLS13)?;
        server_config.load_public_pem(self_signed_cert.as_bytes())?;
        server_config.set_private_key_callback(kms_key)?;

        let server = TlsAcceptor::new(server_config.build()?);

        loop {
            let (stream, _peer_addr) = listener.accept().await?;

            let server = server.clone();
            tokio::spawn(async move {
                let mut tls = server.accept(stream).await.unwrap();

                // server writes message to client
                tls.write_all(MESSAGE).await.unwrap();

                // server waits for client to initiate shutdown
                let read = tls.read(&mut [0]).await.unwrap();
                assert_eq!(read, 0);

                // server completes shutdown
                tls.shutdown().await.unwrap();

                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            });
        }
    });

    let client = tokio::spawn(async move {
        let mut client_config = s2n_tls::config::Config::builder();
        client_config.set_security_policy(&security::DEFAULT_TLS13)?;
        client_config.trust_pem(cert_copy.as_bytes())?;

        // Create the TlsConnector based on the configuration.
        let client = TlsConnector::new(client_config.build()?);

        // Connect to the server.
        let stream = TcpStream::connect(addr).await?;
        let mut tls = client.connect(DEMO_DOMAIN, stream).await?;
        println!("client successfully connected");
        println!("{:#?}", tls);

        // client reads expected message from server
        let mut buffer = [0; MESSAGE.len()];
        tls.read_exact(&mut buffer).await?;
        assert_eq!(buffer, MESSAGE);

        // client initiates shutdown
        tls.shutdown().await?;

        // client waits for server to shutdown
        let read = tls.read(&mut [0]).await?;
        assert_eq!(read, 0);

        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });

    client.await.unwrap().unwrap();
    server_loop.abort();

    Ok(())
}

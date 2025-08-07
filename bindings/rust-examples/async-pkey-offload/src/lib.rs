// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use aws_sdk_kms::{primitives::Blob, types::KeySpec, Client};
use pin_project::pin_project;
use rcgen::CertificateParams;
use s2n_tls::{
    callbacks::{OperationType, PrivateKeyOperation},
    connection::Connection,
};
use yasna::ASN1Result;

pub const KEY_DESCRIPTION: &str = "KMS Asymmetric Key for s2n-tls pkey offload demo";
pub const DEMO_REGION: &str = "us-west-2";
pub const DEMO_DOMAIN: &str = "async-pkey.demo.s2n";

/// Return a list of available demo keys.
///
/// There might be multiple keys if a pending deletion is manually cancelled.
pub async fn get_demo_keys(client: &Client) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let key_list = client.list_keys().send().await?;
    if key_list.truncated {
        // assumption: key list should be small enough to not require pagination
        return Err("key list should not be truncated".into());
    }

    let key_list = match key_list.keys {
        Some(list) => list,
        None => return Ok(Vec::new()),
    };

    let mut matching_keys = Vec::new();
    for k in key_list {
        let describe_output = client
            .describe_key()
            .key_id(k.key_id().unwrap())
            .send()
            .await?;

        let metadata = match describe_output.key_metadata {
            Some(metadata) => metadata,
            None => continue,
        };

        // this key is already scheduled for deletion
        if metadata.deletion_date.is_some() {
            continue;
        }

        if metadata.description() == Some(KEY_DESCRIPTION) {
            matching_keys.push(k.key_id().unwrap().to_owned());
        }
    }
    Ok(matching_keys)
}

/// Get a key from KMS, returning an existing key if found, or creating a new one.
///
/// It will return the first key where
/// - it is not scheduled for deletion
/// - the key description matches [KEY_DESCRIPTION]
pub async fn get_key(client: &Client) -> Result<String, Box<dyn std::error::Error>> {
    let mut demo_keys = get_demo_keys(client).await?;
    if let Some(key_id) = demo_keys.pop() {
        return Ok(key_id);
    }

    // no keys were found, so create one.
    let create_key_resp = client
        .create_key()
        .key_spec(KeySpec::EccNistP384)
        .key_usage(aws_sdk_kms::types::KeyUsageType::SignVerify)
        .description(KEY_DESCRIPTION)
        .send()
        .await?;
    println!("creating new key");
    let key = create_key_resp.key_metadata.unwrap().key_id;
    Ok(key)
}

/// This represents an asymmetric key created in KMS. For more information see the
/// [KMS Developer Guide](https://docs.aws.amazon.com/kms/latest/developerguide/symmetric-asymmetric.html).
///
/// It implements [rcgen::RemoteKeyPair] which allows us to create a self-signed
/// x509 cert corresponding to the key pair.
///
/// It implements [s2n_tls::callbacks::PrivateKeyCallback] which allows us to offload
/// cryptographic operations from s2n-tls to the KMS key.
#[derive(Debug, Clone)]
pub struct KmsAsymmetricKey {
    /// AWS KMS SDK client.
    kms_client: Client,
    /// A copy of the public key in "raw" format
    public_key: Vec<u8>,
    /// The KMS key id
    key_id: String,
}

impl KmsAsymmetricKey {
    const EXPECTED_SIG: s2n_tls::enums::SignatureAlgorithm =
        s2n_tls::enums::SignatureAlgorithm::ECDSA;

    /// Encapsulate an existing KmsAsymmetricKey
    ///
    /// This method does not create a new key in KMS. It will retrieve the public
    /// key of an existing key to be used locally.
    pub async fn new(client: Client, key_id: String) -> Result<Self, Box<dyn std::error::Error>> {
        let public_key_output = client
            .get_public_key()
            .key_id(key_id.clone())
            .send()
            .await?;
        // > The public key that AWS KMS returns is a DER-encoded X.509 public key,
        // > also known as SubjectPublicKeyInfo (SPKI), as defined in RFC 5280.
        // > When you use the HTTP API or the AWS CLI, the value is Base64-encoded.
        // > Otherwise, it is not Base64-encoded.
        // > https://docs.aws.amazon.com/kms/latest/developerguide/download-public-key.html
        // Note that the rust sdk seems to handle common encoding tasks for
        // us, so `encoded_public_key` is binary, not base64 encoded.
        let encoded_public_key = public_key_output.public_key.unwrap().into_inner();
        let raw_public_key = extract_ex_public_key(&encoded_public_key)?;

        Ok(Self {
            kms_client: client,
            public_key: raw_public_key,
            key_id,
        })
    }

    /// Perform an async pkey offload.
    ///
    /// 1. takes the private key operation and converts it to a KMS keyspec
    /// 2. calls KMS to create a signature
    ///
    /// s2n-tls requires that future have 'static bounds, so this function can not
    /// operation on `&self`. Instead we clone all of the necessary elements and
    /// capture them in the closure.
    async fn async_pkey_offload_with_self(
        client: Client,
        key_id: String,
        operation: s2n_tls::callbacks::PrivateKeyOperation,
    ) -> Result<(PrivateKeyOperation, Vec<u8>), s2n_tls::error::Error> {
        let hash = match operation.kind()? {
            // success!
            OperationType::Sign(Self::EXPECTED_SIG, hash_algorithm) => Ok(hash_algorithm),

            // errors
            OperationType::Sign(s, _) => Err(s2n_tls::error::Error::application(
                format!("Unsupported signature type: {s:?}").into(),
            )),
            OperationType::Decrypt => Err(s2n_tls::error::Error::application(
                "Decrypt operation not supported".into(),
            )),
            _ => Err(s2n_tls::error::Error::application(
                format!("Unrecognized operation type: {:?}", operation.kind()).into(),
            )),
        }?;

        // the hash must be available in KMS
        let kms_key_spec = match hash {
            s2n_tls::enums::HashAlgorithm::SHA256 => {
                aws_sdk_kms::types::SigningAlgorithmSpec::EcdsaSha256
            }
            s2n_tls::enums::HashAlgorithm::SHA384 => {
                aws_sdk_kms::types::SigningAlgorithmSpec::EcdsaSha384
            }
            s2n_tls::enums::HashAlgorithm::SHA512 => {
                aws_sdk_kms::types::SigningAlgorithmSpec::EcdsaSha512
            }
            h => {
                return Err(s2n_tls::error::Error::application(
                    format!("requested hash type {h:?} is not supported by KMS").into(),
                ))
            }
        };

        //> If this is an OperationType::Sign operation, then this input has
        //> already been hashed and is the resultant digest.
        //> https://docs.rs/s2n-tls/latest/s2n_tls/callbacks/struct.PrivateKeyOperation.html#method.input
        let mut data_to_sign = vec![0; operation.input_size().unwrap()];
        operation.input(&mut data_to_sign).unwrap();

        // This is necessary as ConnectionFuture requires Sync
        // but this is not implemented by many Futures, including
        // those returned by the aws_sdk_kms client
        let spawned_result = tokio::spawn({
            let client = client.clone();
            let key_id = key_id.clone();
            async move {
                client
                    .sign()
                    .key_id(key_id)
                    .message_type(aws_sdk_kms::types::MessageType::Digest)
                    .message(Blob::new(data_to_sign))
                    .signing_algorithm(kms_key_spec)
                    .send()
                    .await
                    .unwrap()
            }
        });
        let signature_output = spawned_result.await.unwrap();

        let signature = signature_output.signature.unwrap().into_inner();
        Ok((operation, signature))
    }
}

#[pin_project]
pub struct PrivateKeyFuture<F> {
    #[pin]
    fut: F,
}

impl<F> PrivateKeyFuture<F>
where
    F: 'static
        + Send
        + Future<Output = Result<(PrivateKeyOperation, Vec<u8>), s2n_tls::error::Error>>,
{
    pub fn new(fut: F) -> Self {
        PrivateKeyFuture { fut }
    }
}

impl<F> s2n_tls::callbacks::ConnectionFuture for PrivateKeyFuture<F>
where
    F: 'static
        + Send
        + Sync
        + Future<Output = Result<(PrivateKeyOperation, Vec<u8>), s2n_tls::error::Error>>,
{
    fn poll(
        self: Pin<&mut Self>,
        connection: &mut Connection,
        ctx: &mut Context,
    ) -> Poll<Result<(), s2n_tls::error::Error>> {
        let this = self.project();
        let (op, out) = match this.fut.poll(ctx) {
            Poll::Ready(out) => out?,
            Poll::Pending => return Poll::Pending,
        };
        op.set_output(connection, &out)?;
        Poll::Ready(Ok(()))
    }
}

impl s2n_tls::callbacks::PrivateKeyCallback for KmsAsymmetricKey {
    fn handle_operation(
        &self,
        // The connection can not be captured in the future, because the future
        // requires 'static lifetime.
        _connection: &mut s2n_tls::connection::Connection,
        operation: s2n_tls::callbacks::PrivateKeyOperation,
    ) -> Result<
        Option<std::pin::Pin<Box<dyn s2n_tls::callbacks::ConnectionFuture>>>,
        s2n_tls::error::Error,
    > {
        // This is the async closure that will actually call out to KMS.
        let signing_future = KmsAsymmetricKey::async_pkey_offload_with_self(
            self.kms_client.clone(),
            self.key_id.clone(),
            operation,
        );

        // We wrap the async closure in a PrivateKeyFuture. PrivateKeyFuture
        // implements s2n_tls::callbacks::ConnectionFuture, so s2n-tls knows how to poll
        // this type to completion.
        let wrapped_future = PrivateKeyFuture::new(signing_future);

        // Finally we pin the future, allowing it to be safely polled.
        Ok(Some(Box::pin(wrapped_future)))
    }
}

impl rcgen::RemoteKeyPair for KmsAsymmetricKey {
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let signature: Result<Vec<u8>, Box<dyn std::error::Error>> =
            // This trait require a "sync" function. Use `block_in_place` to run 
            // the async function inside a sync context.
            tokio::task::block_in_place(|| {
                let current_runtime = tokio::runtime::Handle::current();

                current_runtime.block_on(async {
                    let output = self
                        .kms_client
                        .sign()
                        .key_id(self.key_id.clone())
                        .message(Blob::new(msg.to_owned()))
                        .signing_algorithm(aws_sdk_kms::types::SigningAlgorithmSpec::EcdsaSha384)
                        .send()
                        .await?;
                    let signature = output.signature.unwrap().into_inner();
                    Ok(signature)
                })
            });
        Ok(signature.unwrap())
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P384_SHA384
    }
}

/// return a pem encoded self-signed certificate
pub fn create_self_signed_cert(
    kms_key: KmsAsymmetricKey,
) -> Result<String, Box<dyn std::error::Error>> {
    let key_pair = rcgen::KeyPair::from_remote(Box::new(kms_key))?;

    let params = CertificateParams::new(vec![DEMO_DOMAIN.to_owned()])?.self_signed(&key_pair)?;
    Ok(params.pem())
}

/// Parse a der-encoded SubjectPublicKeyInfo into a raw public key.
///  
/// A SubjectPublicKeyInfo is defined as follows
/// ```text
/// SubjectPublicKeyInfo  ::=  SEQUENCE  {
///     algorithm            AlgorithmIdentifier,
///     subjectPublicKey     BIT STRING  }
/// ```
/// This function just skips over the algorithm identifier and returns the raw
/// subjectPublicKey field.
pub fn extract_ex_public_key(spki_der: &[u8]) -> ASN1Result<Vec<u8>> {
    yasna::parse_der(spki_der, |reader| {
        reader.read_sequence(|reader| {
            // read the algorithm identifier (ECDSA, etc.)
            reader.next().read_sequence(|reader| {
                // Read past the OID identifying the algorithm (e.g., ECDSA with SHA-256)
                let _algorithm_oid = reader.next().read_oid()?;

                // Read past the second OID which identifies the curve (e.g., prime256v1)
                let _curve_oid = reader.next().read_oid()?;

                Ok(())
            })?;
            // Read the BIT STRING (the actual public key)
            let (public_key_bytes, _size) = reader.next().read_bitvec_bytes()?;

            // The public key inside the BIT STRING should be in uncompressed format (0x04 || x || y)
            assert_eq!(
                public_key_bytes[0], 0x04,
                "Public Key should use an uncompressed format"
            );

            // Return the raw public key
            Ok(public_key_bytes)
        })
    })
}

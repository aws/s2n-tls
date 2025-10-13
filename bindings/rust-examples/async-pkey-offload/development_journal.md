## Development Journal

This document was created during the development of asynchronous callback functionality for s2n-tls Rust bindings.

### Purpose

> [!NOTE]  
> This document serves as a technical walkthrough rather than end-user documentation. 
> It demonstrates the iterative development process required to implement asynchronous 
> callbacks, starting with an initial implementation and addressing compiler errors 
> and design constraints until reaching the final solution.

### Initial Implementation: Direct Approach

The most straightforward API design involves a key abstraction structure:

```rust
#[derive(Debug, Clone)]
pub struct KmsAsymmetricKey {
    /// AWS KMS SDK client.
    kms_client: Client,
    /// A copy of the public key in "raw" format
    public_key: Vec<u8>,
    /// The KMS key id
    key_id: String,
}
```

The initial approach attempted to implement an asynchronous method operating on this key:

```rust
impl KmsAsymmetricKey {
    /// Perform an async pkey offload.
    ///
    /// 1. takes the private key operation and converts it to a KMS keyspec
    /// 2. calls KMS to create a signature
    /// 3. sets the result on the private key operation with the connection
    async fn async_pkey_offload(
        &self,
        connection: &mut s2n_tls::connection::Connection,
        operation: s2n_tls::callbacks::PrivateKeyOperation,
    ) -> Result<(), s2n_tls::error::Error> {
}
```

**Challenge 1: Integration with s2n-tls**

The primary challenge involves integrating asynchronous functionality with s2n-tls, which requires implementing the `PrivateKeyCallback` trait:

```rust
pub trait PrivateKeyCallback: 'static + Send + Sync {
    fn handle_operation(
        &self,
        connection: &mut Connection,
        operation: PrivateKeyOperation,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, Error>;
}
```

> [!NOTE]
> s2n-tls callbacks operate in two distinct modes:
> - Synchronous callbacks perform all work within the callback method and return `Ok(None)`
> - Asynchronous callbacks perform minimal work in the callback method, returning a future 
>   that must be polled repeatedly for completion
> 
> These represent separate execution paths within the callback system.

The initial implementation attempt:

```rust
impl s2n_tls::callbacks::PrivateKeyCallback for KmsAsymmetricKey {
    fn handle_operation(
        &self,
        connection: &mut s2n_tls::connection::Connection,
        operation: s2n_tls::callbacks::PrivateKeyOperation,
    ) -> Result<
        Option<std::pin::Pin<Box<dyn s2n_tls::callbacks::ConnectionFuture>>>,
        s2n_tls::error::Error,
    > {
        let hash = match operation.kind()? { ... }?;
        let kms_key_spec = match hash { ... };

        // Return the raw future without awaiting
        let signing_future = self.async_pkey_offload(
            connection,
            operation,
        );

        Ok(Some(Box::pin(signing_future)))
    }
}
```

This produces the following compilation error:

```
error[E0277]: the trait bound `impl Future<Output = Result<(..., ...), ...>>: ConnectionFuture` is not satisfied
   --> async-pkey-offload/src/lib.rs:302:17
    |
302 |         Ok(Some(Box::pin(signing_future)))
    |                 ^^^^^^^^^^^^^^^^^^^^^^^^ the trait `ConnectionFuture` is not implemented for `impl Future<Output = Result<(PrivateKeyOperation, Vec<u8>), s2n_tls::error::Error>>`
```

### Second Implementation: ConnectionFuture Trait

The compiler indicates that standard futures cannot be returned directly; instead, the `ConnectionFuture` trait must be implemented:

```rust
/// The Future associated with the async connection callback.
///
/// The calling application can provide an instance of [`ConnectionFuture`]
/// when implementing an async callback, eg. [`crate::callbacks::ClientHelloCallback`],
/// if it wants to run an asynchronous operation (disk read, network call).
/// The application can return an error ([Err(Error::application())])
/// to indicate connection failure.
pub trait ConnectionFuture: 'static + Send + Sync {
    fn poll(
        self: Pin<&mut Self>,
        connection: &mut Connection,
        ctx: &mut core::task::Context,
    ) -> Poll<Result<(), Error>>;
}
```

This differs from the standard [`std::future::Future`](https://doc.rust-lang.org/std/future/trait.Future.html) trait:

```rust
pub trait Future {
    type Output;

    // Required method
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output>;
}
```

Since async functions return anonymous, unnameable types, a wrapper structure is required:

```rust
pub struct SimplePrivateKeyFuture<F> {
    future: F,
}

impl<F> s2n_tls::callbacks::ConnectionFuture for SimplePrivateKeyFuture<F>
where
    F: 'static
        + Send
        + Sync
        + Future<Output = Result<(), s2n_tls::error::Error>>,
{
    fn poll(
        self: Pin<&mut Self>,
        connection: &mut Connection,
        ctx: &mut core::task::Context,
    ) -> Poll<Result<(), s2n_tls::error::Error>> {
        self.future.poll(ctx)
    }
}
```

The `Send`/`Sync`/`'static` bounds are required by the `ConnectionFuture` trait definition.

Compilation fails with:

```
error[E0599]: no method named `poll` found for type parameter `F` in the current scope
   --> async-pkey-offload/src/lib.rs:258:21
    |
246 | impl<F> s2n_tls::callbacks::ConnectionFuture for SimplePrivateKeyFuture<F>
    |      - method `poll` not found for this type parameter
...
258 |         self.future.poll(ctx)
    |                     ^^^^ method not found in `F`
```

The compiler suggests using pin projection, but direct application results in move errors. The solution requires implementing structural pinning:

```rust
impl<F> SimplePrivateKeyFuture<F> {
    fn project_future(self: Pin<&mut Self>) -> Pin<&mut F> {
        // This is safe because `field` is pinned when `self` is pinned
        unsafe { self.map_unchecked_mut(|s| &mut s.future) }
    }
}
```

> [!WARNING]  
> This implementation involves unsafe code with specific safety requirements.
> Production implementations should use established crates like `pin-project-lite`
> that provide safe abstractions for pin projection.

The corrected `ConnectionFuture` implementation:

```rust
impl<F> s2n_tls::callbacks::ConnectionFuture for SimplePrivateKeyFuture<F>
where
    F: 'static + Send + Sync + Future<Output = Result<(), s2n_tls::error::Error>>,
{
    fn poll(
        self: Pin<&mut Self>,
        connection: &mut Connection,
        ctx: &mut core::task::Context,
    ) -> Poll<Result<(), s2n_tls::error::Error>> {
        self.project_future().poll(ctx)
    }
}
```

### Third Implementation: PrivateKeyCallback Integration

Returning to the callback implementation:

```rust
impl s2n_tls::callbacks::PrivateKeyCallback for KmsAsymmetricKey {
    fn handle_operation(
        &self,
        connection: &mut s2n_tls::connection::Connection,
        operation: s2n_tls::callbacks::PrivateKeyOperation,
    ) -> Result<
        Option<std::pin::Pin<Box<dyn s2n_tls::callbacks::ConnectionFuture>>>,
        s2n_tls::error::Error,
    > {
        let signing_future = self.async_pkey_offload_with_self(connection, operation);

        let wrapped_future = SimplePrivateKeyFuture {
            future: signing_future,
        };

        Ok(Some(Box::pin(wrapped_future)))
    }
}
```

This generates a complex error message indicating that the AWS SDK futures do not implement the `Sync` trait required by s2n-tls. The error stems from the fact that most futures are `Send` but not `Sync`, while s2n-tls requires both traits.

**Solution: Task Spawning**

The resolution involves spawning the KMS operation in a separate Tokio task, which provides the required `Sync` implementation:

```rust
let spawned_result = tokio::spawn(async move {
    self.kms_client
        .sign()
        .key_id(self.key_id.clone())
        .message_type(aws_sdk_kms::types::MessageType::Digest)
        .message(Blob::new(data_to_sign))
        .signing_algorithm(kms_key_spec)
        .send()
        .await
        .unwrap()
});
let signature_output = spawned_result.await.unwrap();
```

This approach encounters borrowing issues due to the `'static` lifetime requirement of spawned tasks:

```
error[E0521]: borrowed data escapes outside of method
   --> async-pkey-offload/src/lib.rs:225:30
    |
182 |           &self,
    |           -----
    |           |
    |           `self` is a reference that is only valid in the method body
    |           let's call the lifetime of this reference `'1`
...
225 |           let spawned_result = tokio::spawn(async move {
    |  ______________________________^
```

The solution requires cloning the necessary data:

```rust
let spawned_result = tokio::spawn({
    let client = self.kms_client.clone();
    let key_id = self.key_id.clone();
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
```

**Challenge 2: Lifetime Requirements**

Additional lifetime errors occur due to the `'static` requirement of the `ConnectionFuture` trait:

```
error: lifetime may not live long enough
   --> async-pkey-offload/src/lib.rs:342:17
    |
324 |         &self,
    |         - let's call the lifetime of this reference `'1`
...
342 |         Ok(Some(Box::pin(wrapped_future)))
    |                 ^^^^^^^^^^^^^^^^^^^^^^^^ coercion requires that `'1` must outlive `'static`
```

The trait signature requires `'static` lifetime bounds:

```
expected `fn(&'1 KmsAsymmetricKey, &'2 mut Connection, PrivateKeyOperation) -> Result<Option<Pin<Box<(dyn ConnectionFuture + 'static)>>>, s2n_tls::error::Error>`
found `fn(&'1 KmsAsymmetricKey, &'2 mut Connection, PrivateKeyOperation) -> Result<Option<Pin<Box<(dyn ConnectionFuture + '1)>>>, s2n_tls::error::Error>`
```

**Final Solution: Decoupled Architecture**

The resolution involves removing all borrowed references from the async operation. The method signature changes from:

```rust
async fn async_pkey_offload_with_self(
    &self,
    connection: &mut s2n_tls::connection::Connection,
    operation: s2n_tls::callbacks::PrivateKeyOperation,
) -> Result<(), s2n_tls::error::Error>
```

to:

```rust
async fn async_pkey_offload_with_self(
    client: Client,
    key_id: String,
    connection: &mut s2n_tls::connection::Connection,
    operation: s2n_tls::callbacks::PrivateKeyOperation,
) -> Result<(), s2n_tls::error::Error>
```

Additionally, the connection reference is removed from the async operation entirely. The connection is only accessed during the final polling phase:

```rust
impl<F> s2n_tls::callbacks::ConnectionFuture for SimplePrivateKeyFuture<F>
where
    F: 'static + Send + Sync + Future<Output = Result<(Vec<u8>, PrivateKeyOperation), s2n_tls::error::Error>>,
{
    fn poll(
        self: Pin<&mut Self>,
        connection: &mut Connection,
        ctx: &mut core::task::Context,
    ) -> Poll<Result<(), s2n_tls::error::Error>> {
        let (signature, op) = match self.project_future().poll(ctx) {
            Poll::Ready(result) => result?,
            Poll::Pending => return Poll::Pending,
        };
        op.set_output(connection, &signature)?;
        Poll::Ready(Ok(()))
    }
}
```

This architecture separates the KMS operation (which runs independently) from the connection manipulation (which occurs only when the signature is ready), satisfying all lifetime and trait requirements for successful compilation and execution.

## Development Journal
### Why is it so ugly?

> [!NOTE]  
> This document is not intended as "documentation", but rather as an artifact 
> that walks through why async callbacks look the way they do.
>
> We start with a "naive" implementation of the callback, and walk through the encountered
> compiler errors and issues until we arrive at the final product.

### Attempt 1: Naive Approach
What is the most "natural" shape for the API to take? I would say that it makes
sense to have some sort of "key" abstraction , like so
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

Then ideally we'd just have an async method which operates on that key, something like this:
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

Now it feels like we should have everything that we need to do the async pkey offload.

**😱 roadblock 1 😱**: How do we actually use this with s2n-tls?

The trickery begin here. I have a thing that does async stuff, how can I actually shove that into s2n-tls?

Well, the callback requires that the struct implements the `PrivateKeyCallback` trait.
```rust
pub trait PrivateKeyCallback: 'static + Send + Sync {
    fn handle_operation(
        &self,
        connection: &mut Connection,
        operation: PrivateKeyOperation,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, Error>;
}
```
Immediately, my brain starts to hurt. That doesn't look async at all. And why are there so many types? Umm, let's just give it our best shot?

> [!NOTE]
> A useful distinction when thinking about s2n-tls callbacks is that they are very bimodal. 
> A synchronous callback will do all of the work on the actual callback, then returning `Ok(None)`.
> An async callback will do generally do _no_ work on the actual callback, instead returning a future
> that most be polled repeatedly for work to happen.
> 
> In summary, async vs sync are two totally separate paths of execution (and this writer is
> uncertain of whether we made the right API choice exposing them that way)

So the first attempt looks like this
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

        // we don't call await so we get the raw future, which implements
        // Future<Output = Result<(), Error>>
        let signing_future = self.async_pkey_offload(
            connection,
            operation,
        );

        Ok(Some(Box::pin(signing_future)))
    }
}
```

This results in the following compilation error.
```
error[E0277]: the trait bound `impl Future<Output = Result<(..., ...), ...>>: ConnectionFuture` is not satisfied
   --> async-pkey-offload/src/lib.rs:302:17
    |
302 |         Ok(Some(Box::pin(signing_future)))
    |                 ^^^^^^^^^^^^^^^^^^^^^^^^ the trait `ConnectionFuture` is not implemented for `impl Future<Output = Result<(PrivateKeyOperation, Vec<u8>), s2n_tls::error::Error>>`
```

### Attempt 2: Implement ConnectionFuture
Okay, the compiler is telling us that we can't return a basic future, we need this fancy `ConnectionFuture`

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

This is similar, but different to the [`std::future::Future`](https://doc.rust-lang.org/std/future/trait.Future.html) trait.
```rust
pub trait Future {
    type Output;

    // Required method
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output>;
}
```

> [!NOTE]
> I don't understand why we did this. It seems like we are requiring a _superset_ 
> of the "future" functionality. E.g. anything that is a `std::future::Future` could
> semantically be a `ConnectionFuture`, because it could just ignore the connection
> argument. 
>
> It's perhaps related that the future has to be polled _through_ the connection?
> It still feels like there should be a way around this. In my head, it feels like
> there should be a generic way to handle futures in the rust layer, and the C layer
> shouldn't even know about it.
>
> And don't ask me to expand, because I'm still not totally sure what I mean by
> that. More thought needed.

So let's go ahead and implement ConnectionFuture. Except, uhhh, what do we implement `ConnectionFuture` on? We can't implement connection future on `KmsAsymmetricKey`, that isn't something that can be "polled". Rather we need to implement `ConnectionFuture` on the type/future returned by the `KmsAsymmetricKey::async_pkey_offload` method. 

The issue is that that isn't an explicit type, and is in fact anonymous and un-nameable
> When Rust sees a block marked with the async keyword, it compiles it into a unique, anonymous data type that implements the Future trait. When Rust sees a function marked with async, it compiles it into a non-async function whose body is an async block. An async function’s return type is the type of the anonymous data type the compiler creates for that async block.
> [The Rust Book: Futures and Syntax](https://doc.rust-lang.org/book/ch17-01-futures-and-syntax.html)

The solution is to wrap the anonymous future in some other type, something like the following:
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
        // This is a future, so we can poll it?
        self.future.poll(ctx)
    }
}
```

The `Send`/`Sync`/`'static` bounds are required by the `ConnectionFuture` trait definition.

The `Future` bound is just saying that "`F` implements the following future trait". This is the trait that our `async fn async_pkey_offload` returns;

Okay, let's compile!

Nope:
```
error[E0599]: no method named `poll` found for type parameter `F` in the current scope
   --> async-pkey-offload/src/lib.rs:258:21
    |
246 | impl<F> s2n_tls::callbacks::ConnectionFuture for SimplePrivateKeyFuture<F>
    |      - method `poll` not found for this type parameter
...
258 |         self.future.poll(ctx)
    |                     ^^^^ method not found in `F`
    |
help: consider pinning the expression
    |
258 ~         let mut pinned = std::pin::pin!(self.future);
259 ~         pinned.as_mut().poll(ctx)
    |
```

But the compiler helpfully suggested a solution. Let's try it!

```
error[E0507]: cannot move out of dereference of `Pin<&mut SimplePrivateKeyFuture<F>>`
   --> async-pkey-offload/src/lib.rs:258:41
    |
258 |         let mut pinned = std::pin::pin!(self.future);
    |                                         ^^^^^^^^^^^ move occurs because value has type `F`, which does not implement the `Copy` trait
    |
help: if `F` implemented `Clone`, you could clone the value
   --> async-pkey-offload/src/lib.rs:246:6
    |
246 | impl<F> s2n_tls::callbacks::ConnectionFuture for SimplePrivateKeyFuture<F>
    |      ^ consider constraining this type parameter with `Clone`
...
258 |         let mut pinned = std::pin::pin!(self.future);
    |                                         ----------- you could clone this value
```

No dice. And cloning feels suspicious. Like the main struct is already pinned, isn't it trivially obvious that the field can also be pinned? It feels like that should work...

The process of making this work is called "projecting" and you can read all about that here: [Projections and Structural Pinning](https://doc.rust-lang.org/std/pin/index.html#projections-and-structural-pinning).

More specifically, we're gonna steal the snippet of code from [here](https://doc.rust-lang.org/std/pin/index.html#choosing-pinning-to-be-structural-for-field) to allows us to access the pinned field
```rust
impl<F> SimplePrivateKeyFuture<F> {
    fn project_future(self: Pin<&mut Self>) -> Pin<&mut F> {
        // This is okay because `field` is pinned when `self` is.
        unsafe { self.map_unchecked_mut(|s| &mut s.future) }
    }
}
```

> [!WARNING]  
> There are lots of safety implications with this that I am just gonna ignore. There
> are crates to implement this pinning projection for you, which are apparently 
> safe for reasons that I haven't fully considered, see [pin-project-lite/safety](https://github.com/taiki-e/pin-project-lite?tab=readme-ov-file#similar-safety)

Okay, now our ConnectionFuture trait is working
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

### Attempt 3: Implement s2n_tls::callbacks::PrivateKeyCallback

Okay, let's get back to our actual callback.

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
        // This is the async closure that will actually call out to KMS.
        let signing_future = self.async_pkey_offload_with_self(connection, operation);

        // We wrap the async closure in a SimplePrivateKeyFuture. SimplePrivateKeyFuture
        // implements s2n_tls::callbacks::ConnectionFuture, so s2n-tls knows how to poll
        // this type to completion.
        let wrapped_future = SimplePrivateKeyFuture {
            future: signing_future,
        };

        // Finally we pin the future, allowing it to be safely polled.
        Ok(Some(Box::pin(wrapped_future)))
    }
}
```

And we get a _massive_ error message
```
error[E0277]: `dyn Future<Output = Result<Response, ConnectorError>> + Send` cannot be shared between threads safely
    --> async-pkey-offload/src/lib.rs:336:17
     |
336  |         Ok(Some(Box::pin(wrapped_future)))
     |                 ^^^^^^^^^^^^^^^^^^^^^^^^ `dyn Future<Output = Result<Response, ConnectorError>> + Send` cannot be shared between threads safely
     |
     = help: the trait `Sync` is not implemented for `dyn Future<Output = Result<Response, ConnectorError>> + Send`
     = help: the trait `ConnectionFuture` is implemented for `SimplePrivateKeyFuture<F>`
     = note: required for `Unique<dyn Future<Output = Result<Response, ConnectorError>> + Send>` to implement `Sync`
note: required because it appears within the type `Box<dyn Future<Output = Result<Response, ConnectorError>> + Send>`
    --> /home/ubuntu/.rustup/toolchains/stable-aarch64-unknown-linux-gnu/lib/rustlib/src/rust/library/alloc/src/boxed.rs:231:12
     |
231  | pub struct Box<
     |            ^^^
note: required because it appears within the type `Pin<Box<dyn Future<Output = Result<Response, ConnectorError>> + Send>>`
    --> /home/ubuntu/.rustup/toolchains/stable-aarch64-unknown-linux-gnu/lib/rustlib/src/rust/library/core/src/pin.rs:1089:12
     |
1089 | pub struct Pin<Ptr> {
     |            ^^^
note: required because it appears within the type `Inner<Result<Response, ConnectorError>, Pin<Box<...>>>`
    --> /home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-smithy-async-1.2.5/src/future/now_or_later.rs:88:10
     |
88   |     enum Inner<T, F> {
     |          ^^^^^
note: required because it appears within the type `NowOrLater<Result<Response, ConnectorError>, Pin<Box<...>>>`
    --> /home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-smithy-async-1.2.5/src/future/now_or_later.rs:69:16
     |
69   |     pub struct NowOrLater<T, F> {
     |                ^^^^^^^^^^
note: required because it appears within the type `aws_smithy_runtime_api::client::http::HttpConnectorFuture`
    --> /home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-smithy-runtime-api-1.8.1/src/client/http.rs:67:16
     |
67   |     pub struct HttpConnectorFuture<'static, HttpResponse, ConnectorError>;
     |                ^^^^^^^^^^^^^^^^^^^
note: required because it appears within the type `aws_smithy_runtime::client::http::body::minimum_throughput::MaybeUploadThroughputCheckFuture`
    --> /home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-smithy-runtime-1.8.3/src/client/http/body/minimum_throughput.rs:341:21
     |
341  |     pub(crate) enum MaybeUploadThroughputCheckFuture {
     |                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
note: required because it's used within this `async` fn body
    --> /home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-smithy-runtime-1.8.3/src/client/orchestrator.rs:356:3
     |
356  |   ) {
     |  ___^
357  | |     run_interceptors!(halt_on_err: read_before_attempt(ctx, runtime_components, cfg));
358  | |
359  | |     let (scheme_id, identity, endpoint) = halt_on_err!([ctx] => resolve_identity(runtime_components, cfg).await.map_err(OrchestratorError...
...    |
460  | |     run_interceptors!(halt_on_err: read_after_deserialization(ctx, runtime_components, cfg));
461  | | }
     | |_^
note: required because it appears within the type `ManuallyDrop<impl Future<Output = ()>>`
    --> /home/ubuntu/.rustup/toolchains/stable-aarch64-unknown-linux-gnu/lib/rustlib/src/rust/library/core/src/mem/manually_drop.rs:157:12
<SNIP>
```

Notably, the error log seems to be discussing AWS SDK/smithy things? What's going on there?

Well, what's going on is that s2n-tls requires it's future to be Send + Sync, but most futures don't implement `Sync`. For more information see this issue: [Rust binding ConnectionFuture requires Sync while most Futures do not](https://github.com/aws/s2n-tls/issues/4981).

The easiest way to get the `Sync` future is to just spawn the the actual KMS call inside it's own Tokio task. This "bundles" the information up in to a safe nugget which does implement `Sync.`

So we'll replace 
```rust
        let signature_output = self
            .kms_client
            .sign()
            .key_id(self.key_id.clone())
            .message_type(aws_sdk_kms::types::MessageType::Digest)
            .message(Blob::new(data_to_sign))
            .signing_algorithm(kms_key_spec)
            .send()
            .await
            .unwrap();
```
with
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

Except that we run into a problem
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
226 | |             self.kms_client
227 | |                 .sign()
228 | |                 .key_id(self.key_id.clone())
...   |
234 | |                 .unwrap()
235 | |         });
    | |          ^
    | |          |
    | |__________`self` escapes the method body here
    |            argument requires that `'1` must outlive `'static`
```

We are borrowing for a task, but that task _could_ live for a long time. Let's throw some `clone`s at the problem.

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
        }}
```

Okay. This solves that problem. And exposes another one.

```
error: lifetime may not live long enough
   --> async-pkey-offload/src/lib.rs:342:17
    |
324 |         &self,
    |         - let's call the lifetime of this reference `'1`
...
342 |         Ok(Some(Box::pin(wrapped_future)))
    |                 ^^^^^^^^^^^^^^^^^^^^^^^^ coercion requires that `'1` must outlive `'static`
    |
help: to declare that the trait object captures data from argument `self`, you can add an explicit `'_` lifetime bound
    |
328 |         Option<std::pin::Pin<Box<dyn s2n_tls::callbacks::ConnectionFuture + '_>>>,
    |                                                                           ++++

error: lifetime may not live long enough
   --> async-pkey-offload/src/lib.rs:342:17
    |
325 |         connection: &mut s2n_tls::connection::Connection,
    |                     - let's call the lifetime of this reference `'2`
...
342 |         Ok(Some(Box::pin(wrapped_future)))
    |                 ^^^^^^^^^^^^^^^^^^^^^^^^ coercion requires that `'2` must outlive `'static`
    |
help: to declare that the trait object captures data from argument `connection`, you can add an explicit `'_` lifetime bound
    |
328 |         Option<std::pin::Pin<Box<dyn s2n_tls::callbacks::ConnectionFuture + '_>>>,
    |                                                                           ++++

warning: `async-pkey-offload` (lib) generated 1 warning
error: could not compile `async-pkey-offload` (lib) due to 2 previous errors; 1 warning emitted
```

If we give up on understanding that and just try to apply the fix, we get a slightly more readable error
```
error: `impl` item signature doesn't match `trait` item signature
   --> async-pkey-offload/src/lib.rs:323:5
    |
323 | /     fn handle_operation(
324 | |         &self,
325 | |         connection: &mut s2n_tls::connection::Connection,
326 | |         operation: s2n_tls::callbacks::PrivateKeyOperation,
...   |
329 | |         s2n_tls::error::Error,
330 | |     > {
    | |_____^ found `fn(&'1 KmsAsymmetricKey, &'2 mut Connection, PrivateKeyOperation) -> Result<Option<Pin<Box<(dyn ConnectionFuture + '1)>>>, s2n_tls::error::Error>`
    |
   ::: /home/ubuntu/workspace/s2n-tls/bindings/rust/extended/s2n-tls/src/callbacks/pkey.rs:127:5
    |
127 | /     fn handle_operation(
128 | |         &self,
129 | |         connection: &mut Connection,
130 | |         operation: PrivateKeyOperation,
131 | |     ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, Error>;
    | |_______________________________________________________________- expected `fn(&'1 KmsAsymmetricKey, &'2 mut Connection, PrivateKeyOperation) -> Result<Option<Pin<Box<(dyn ConnectionFuture + 'static)>>>, s2n_tls::error::Error>`
    |
    = note: expected signature `fn(&'1 KmsAsymmetricKey, &'2 mut Connection, PrivateKeyOperation) -> Result<Option<Pin<Box<(dyn ConnectionFuture + 'static)>>>, s2n_tls::error::Error>`
               found signature `fn(&'1 KmsAsymmetricKey, &'2 mut Connection, PrivateKeyOperation) -> Result<Option<Pin<Box<(dyn ConnectionFuture + '1)>>>, s2n_tls::error::Error>`
    = help: the lifetime requirements from the `impl` do not correspond to the requirements in the `trait`
    = help: verify the lifetime relationships in the `trait` and `impl` between the `self` argument, the other inputs and its output
```

In denser fashion, we have
```
expected `fn(&'1 KmsAsymmetricKey, &'2 mut Connection, PrivateKeyOperation) -> Result<Option<Pin<Box<(dyn ConnectionFuture + 'static)>>>, s2n_tls::error::Error>`
found `fn(&'1 KmsAsymmetricKey, &'2 mut Connection, PrivateKeyOperation) -> Result<Option<Pin<Box<(dyn ConnectionFuture + '1)>>>, s2n_tls::error::Error>`
```

So it expected a future with `'static` lifetime bounds, but we have a future with that was capturing `&self` of the `KmsAsymmetricKey` and also the `&mut Connection`. Naughty naughty.

So how do we fix this? Clones and refactors!

Let's remove the borrow of `self` first.

We'll update the signature from 
```rust
    async fn async_pkey_offload_with_self(
        &self,
        connection: &mut s2n_tls::connection::Connection,
        operation: s2n_tls::callbacks::PrivateKeyOperation,
    ) -> Result<(), s2n_tls::error::Error> {
```
to
```rust
    async fn async_pkey_offload_with_self(
        client: Client,
        key_id: String,
        connection: &mut s2n_tls::connection::Connection,
        operation: s2n_tls::callbacks::PrivateKeyOperation,
    ) -> Result<(), s2n_tls::error::Error> {
```

This gets rid of the borrow of `self`. To get rid of the borrow of `connection`, we need to actually completely remove the connection from the `async_pkey_offload` method. This way we'll be able to poll the future until we get the actual signature back, and then we'll delay touching the connection until we have completely polled the future, and then we'll modify the connection in the `ConnectionFuture::poll` implementation.

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

Here we see the modified poll functionality. The kms async call future does not capture the connection, and we just slip it in at the end of the `ConnectionFuture::poll` method. 

And voila, you now have async pkey offloading!

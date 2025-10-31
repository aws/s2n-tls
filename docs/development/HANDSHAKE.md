# Negotiating the TLS Handshake

To perform a TLS handshake, the customer calls "s2n_negotiate". But when the customer calls s2n_negotiate, what actually happens?

Note: If you are unfamiliar with s2n_negotiate, read [the usage guide](https://github.com/aws/s2n-tls/blob/main/docs/usage-guide/topics/ch07-io.md#performing-the-tls-handshake) first. This discussion will assume familiarity with the public usage, behavior, and requirements of s2n_negotiate.

## The Handshake Arrays

The TLS protocol defines very specific allowed orderings for the messages in the TLS handshake. See the state machines defined in the TLS1.3 RFC: https://datatracker.ietf.org/doc/html/rfc8446#appendix-A The ordering of messages can vary depending on factors like whether or not the server requires client authentication.

Many TLS libraries implement the handshake via a traditional state machine like the one defined in the RFC. However, state machines are difficult to implement correctly and the TLS state machine is fairly complex. Mistakes can result in fatal errors, incorrect message orderings, or infinite loops.

But s2n-tls takes a different approach. We define all possible legal orderings of handshake messages, so that illegal orderings or infinite loops are impossible by design. We then collect all those allowed message orderings into an array and index into that array with a value we call the "handshake type". The handshake type is defined as a bitfield where each bit represents a particular TLS feature or choice that can affect message ordering. For example, `NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH` indicates a handshake which requires client authentication. Note: "NEGOTIATED" means that the handshake has progressed past the ServerHello, and "FULL_HANDSHAKE" indicates that authentication will be required because session resumption was not used.

Here is an example entry in what we refer to as the "handshake arrays":
```
    [NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH] = {
            CLIENT_HELLO,
            SERVER_HELLO, ENCRYPTED_EXTENSIONS, SERVER_CERT_REQ, SERVER_CERT, SERVER_CERT_VERIFY, SERVER_FINISHED,
            CLIENT_CERT, CLIENT_CERT_VERIFY, CLIENT_FINISHED,
            APPLICATION_DATA
    },
```

So if the handshake type is set to `NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH` during negotiation, then this is the complete list of messages that will be sent and received during the handshake. The list is organized by "flight", meaning that each line represents a set of messages from the same sender, either the client or server. So here, the client first sends the ClientHello message. The server then responds with the ServerHello, EncryptedExtensions, etc. The client then responds with the ClientCert, ClientCertVerify, and finally ClientFinished. At that point, the handshake is complete and ApplicationData can be exchanged.

You can find all the handshake arrays in https://github.com/aws/s2n-tls/blob/main/tls/s2n_handshake_io.c. They are split into "tls13_handshakes" and "handshakes" (legacy TLS1.2 handshakes), because the two state machines diverge significantly after the ServerHello message.

### What if one of the handshakes is wrong?

The handshake arrays are compiled manually, so that is a real, valid concern. However, it is worth noting that the handshake array implementation confines mistakes to basic ordering errors for specific handshake types.

To ensure the correctness of the handshakes, s2n-tls includes formal verification using a tool called "SAW". The SAW handshake proof compares the array implementation to a more traditional state machine written in a language called Cryptol. The TLS1.3 state machine is [here](https://github.com/aws/s2n-tls/blob/6aefe741f17489211f6c28e837c1a65ee66a1ef2/tests/saw/spec/handshake/rfc_handshake_tls13.cry#L140-L287), and the legacy TLS1.2 state machine is [here](https://github.com/aws/s2n-tls/blob/6aefe741f17489211f6c28e837c1a65ee66a1ef2/tests/saw/spec/handshake/rfc_handshake_tls12.cry#L145-L214). If s2n-tls drops SAW as a tool, we should instead replace these proofs with a test comparing the handshake arrays to a more traditional state machine written in another language (like C).

### Debugging

If you know the handshake type of a connection (handshake.handshake_type on s2n_connection), then you can determine the active handshake from the handshake arrays and visually examine the active message ordering. If you know the current index (handshake.message_number on s2n_connection), then you can determine the message that s2n-tls currently expects to send or receive. This can help if a handshake is hanging or timing out. Simply checking that the client and server both agree on the handshake type is also useful.

## The State Machine

Given the handshake arrays, the s2n-tls "state machine" becomes very simple: iterate through the chosen handshake array to perform the handshake. For each message type, we define client and server handlers. So if the handshake array indicates that the current message is EncryptedExtensions, then a server would call the server handler (s2n_encrypted_extensions_send) and the client would call the client handler (s2n_encrypted_extensions_recv). The interesting, message-specific logic lives in those message handlers.

The state machine is implemented as another simple lookup table, where information about each message is indexed by message type and the handlers are then indexed by "mode", or client vs server. You can find the state machines in https://github.com/aws/s2n-tls/blob/main/tls/s2n_handshake_io.c. They are split into "tls13_state_machine" and "state_machine" (legacy TLS1.2 state machine).

Here's an example state machine entry:
```
    [ENCRYPTED_EXTENSIONS]      = {TLS_HANDSHAKE, TLS_ENCRYPTED_EXTENSIONS, 'S', {s2n_encrypted_extensions_send, s2n_encrypted_extensions_recv}},
```

"TLS_HANDSHAKE" indicates the record type of the message. Most messages are TLS_HANDSHAKE, but the ChangeCipherSpec messages are "TLS_CHANGE_CIPHER_SPEC" and ApplicationData is "TLS_APPLICATION_DATA". "TLS_ENCRYPTED_EXTENSIONS" indicates the official TLS handshake message type, which is different from the internal message type value we used to index into the array. "S" indicates that the  "writer" is the server: if the client should send the message instead, then the value would be "C". Finally, "s2n_encrypted_extensions_send" indicates the server message handler, and "s2n_encrypted_extensions_recv" indicates the client message handler.

### Debugging

If you're looking for how a particular message is implemented in s2n-tls, look up the handlers in the state machines. They are arguably the primary entry point into the rest of the library.

## Handshake Messages

The primary unit of data in TLS is a "record". During the handshake, records contain handshake messages (or ChangeCipherSpec messages, which aren't technically handshake messages). A TLS record can contain one handshake message, or multiple handshake messages, or only a fragment of a handshake message.

s2n-tls never bundles multiple handshake messages into a single TLS record. This is for simplicity: writing handshake messages uses the same basic logic as writing application data.

## The handshake.io Buffer

Message handlers read handshake messages from or write handshake messages to the "handshake.io" buffer. The buffer is basically a staging area for handshake messages. The messages are either read into handshake.io from the network, or written to the network from handshake.io like application data.

The handshake.io buffer is set quite large (the maximum fragment size), but will resize if larger handshake message are encountered. Since handshake messages can span records, they can exceed the maximum fragment size.

## Writing a Handshake Message

If the state machine indicates that the next expected message should be written ("writer" matches the current connection mode):

1. Write the message header.

   Write the message type into handshake.io. Since the size of the message isn't known yet, a placeholder size is written.

2. Call the message handler.

   Look up the current message in the handshake arrays, given the handshake type and message number. Look up that message in the state machine and choose the correct handler based on the connection mode.

   The handler will then write the handshake message into handshake.io.

3. Write the record.

   Write the buffered handshake message to the network. See ["Sending Application Data"](APPLICATION_DATA.md#sending-application-data).

   If the network write blocks with data still in handshake.io (for example, if a handshake message is large enough for two records and sending the first record blocks), then the next call to s2n_negotiate will continue to write the buffered handshake message.

4. Continue.

   Iterate the message number, moving the state machine and handshake forwards to the next message.

## Reading a Handshake Message

If the state machine indicates that the next expected message should be read ("writer" does NOT match the current connection mode):

1. Read a record.

   Read a TLS record from the network. See ["Receiving Application Data"](APPLICATION_DATA.md#receiving-application-data).
   
   HOWEVER, reading handshake messages is different from reading application data. Since we expect handshake records rather than application data records, we have to read and parse a single record at a time.

   #### Handle non-handshake records

   Some non-handshake records are valid during the handshake, like ApplicationData during TLS1.3 early data. If the record does not actually contain handshake messages, handle it appropriately. Then read another record (return to step 1).

2. Parse a handshake message.

   Attempt to read a handshake message header from the provided record to determine the type and size of the handshake message.
   
   Verify that the handshake message type matches the currently expected type. We determine the expected type by looking up the current message in the handshake arrays, given the handshake type and message number.

   Copy the handshake message into handshake.io for further parsing.

   If the handshake message is incomplete, then read another record (return to step 1).

4. Call message handler.

   Look up the current message in the handshake arrays, given the handshake type and message number. Look up that message in the state machine and choose the correct handler based on the connection mode.

   The handler will then parse the handshake message currently in handshake.io.

5. Continue.

   Iterate the message number, moving the state machine and handshake forwards to the next message.

   If there are more handshake messages in the record, parse them (return to step 2). Otherwise, read another record (return to step 1).

## Async Callbacks

s2n-tls supports "async callbacks". We allow applications to set callback functions that are triggered at specific points in the handshake. Some callback functions return immediately and do not interrupt the handshake logic. But others are designed to allow the application to pause the handshake while more expensive work is performed.

If the handshake is paused, it has to resume rather than follow the usual logic. It simply looks up the current handler and executes it again. Individual handlers are responsible for resuming without repeating previous work. Because this special-casing requires duplicating parts of the standard negotiation logic (like updating the transcript hash) it adds complexity to the handshake code.

This solution may not scale well as we add more async callbacks, or if we want to reduce the complexity of the handshake code. If considering alternatives, do NOT add more entries to the handshake arrays; for example, do not split CLIENT_HELLO into CLIENT_HELLO_BEFORE_CALLBACK and CLIENT_HELLO_AFTER_CALLBACK. Each entry in the handshake arrays should exactly map to a real handshake message to maintain the simplicity and readability of the state machine. However, we could consider arrays of sequential handlers rather than the current single handlers: essentially, a second layer of array-based state machine.
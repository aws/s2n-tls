# Development guide for s2n

If you're curious about the internals of s2n, or interested in contributing to
s2n, this document is for you. If you're interested in using s2n in an application
that you're writing, see the accompanying usage guide instead.

## s2n's tenets

Before getting into the detail of how s2n works internally, it's worth covering
s2n's tenets, as they guide and inform many of the design decisions we'll go through. 
We're always open to considering new tenets, if you can think of better ones and make 
a case for them. 

### Tenets 
* **Maintain an excellent TLS/SSL implementation**<br/>Although it's hidden "*under the hood*", TLS/SSL is the direct interface with customers and end-users. Good performance and security are critical to a positive experience.
* **Protect user data and keys**<br/>Above all else, s2n must ensure that user data and private keys are being handled correctly and carefully. Security is often a matter of trade-offs and costs; we should always seek to increase the costs for attackers whenever the trade offs are acceptable to users.
* **Stay minimal and simple**<br/>Write as little code as neccessary, omit little-used optional features and support as few modes of operation as possible.
* **Write clear readable code with a light cognitive load**<br/>s2n's code should be consise, easy to follow and legible to a proficient C programmer. Our code should be organized in a way that divides the implementation up into small units of work, with all of the context neccessary at hand. We should also minimize the number of branches in our code, the depth of our call stacks, and the membership of our structures.   
* **Defend in depth and systematically**<br/>Great care and attention to detail is required to write good code, but we should also use automation and mechanistic processess to protect against human error. We should fix bugs (of course), but also fix classes of bugs.
* **Be easy to use and maintain sane defaults**<br/>It should be low effort, even for a novice developer, to use s2n in a safe way. We also shouldn't "*pass the buck*" and place the burden of subtle or complicated TLS-specific decision making on application authors or system administrators. 
* **Provide great performance and responsivity**<br/>TLS/SSL is rapidly becoming ubiquitious, in part due to advances in performance and responsivity. Naturally, people always appreciate speed, but costs are also important. Even small inefficiencies and overhead in s2n can become significant when multiplied by billions of users and quintillions of sessions. 
* **Stay humble and stick to facts**<br/>s2n operates in a security critical space. Even with the most precautionary development methods it is impossible to guarantee the absence of defects. A subtle one-byte error on a single line may still cause problems. Boasting about security practices is destined to backfire and mis-lead. As opinions can differ on security best practises, sometimes in contradictory ways, we should be guided by facts and measurable data.   

## Coding style and conventions 

Per our tenets, an important goal is to reduce the cognitive load required to 
read, review and extend s2n. Although s2n is written in C, s2n adopts several
patterns more common to functional programming, though they are used in a way
that is idiomatic and shouldn't feel completely alien in C. 

### High level function design
The first convention is that's s2n's functions are generally quite small, no
more than a page or two at most and commonly just a few lines. They usually 
have a clear input and output and are in that sense "pure" functions; for 
example handling a particular TLS handshake message type takes the message
as input, and the output is connection state. 

In a very technical sense, the functions are not actually 
pure, as they operate on the members of structs that are passed rather than
treating parameters as immutable, but it would be laborious and less readable
in C to support multi-member return structures. What's more relevant is that
s2n functions generally operate in a message passing way. For example,
a simplified version of the flow when handling a TLS client finished message
might looks like this:

![s2n message passing](s2n_lambda.png "s2n message passing")

each function handles a clear, well-defined piece of work, before passing on
responsibility to the next function. 

The second convention of s2n's functions is that functions are generally
split into two kinds: those that handle control flow and coordinate
other functions, and those that parse messages. Splitting things up this
way leads to a shallower call stack, but the main benefit is that functions
can read quite declaratively. In the case of message parsers, the function
contents can read almost like schemas of the message being passed. s2n is 
also structured in a very message oriented way; for example the functions
for reading and writing a particular message type are usually in the same
file, so that all of context and logic needed to handle that message type
can be seen and thought about in one neat place. 

A good example file to look at is https://github.com/awslabs/s2n/blob/master/tls/s2n_server_finished.c. 
From reading the file it should be reasonably clear that a server
finished message consists just of S2N_TLS_FINISHED_LEN number of bytes, what 
the next state is and what else is going on. 

### Error handling 

### Safety checking

### Control flow and the state machine

### Code formatting

### 

## Readability and short functions

One of the goals of the s2n code layout is to reduce the cognitive load on the
programmer required to write, review and extend s2n functionality. s2n is
generally split into small, readable, discrete functions with a clear input and
output. Human meaningful variable names are encouraged. #ifdefs are
discouraged.

Each TLS/SSL message type is handled in isolation, in its own .c file, with the
client and server handlers written as seperate functions but side by side for
easy comparison.

Code is consistently formatted, and the s2n.mk Makefile includes an indent
recipe suitable for formatting code. Run "make indent" to format the s2n
codebase.

## Error handling in s2n

All s2n functions return -1 or NULL on error.

## Basic safety routines

The s2n_safety.h header defines various safety routines that it is considered
idiomatic to use in s2n. gte_check, lte_check, gt_check, lt_check, eq_check,
ne_check provide basic greater-than-or-equal-to, less-than-or-equal-to,
greater-than, less-than, equality and non-equality checking. These checks can
be used as assertions and a failure will trigger a "return -1" and an
appropriate error string.

Additionally, there are inclusive_range_check() and exclusive_range_check()
routines provided for range checking, and memcpy_check(), a checked version of
memcpy().

As it is so common to call other functions and check their return value, a
convenience macro "GUARD()" is provided. GUARD() will execute a function and
will itself trigger a "return -1" if the function does not execute
successfully.

## Memory handling in s2n

As passing around regions of memory is so common, s2n provides an s2n_blob
structure for tracking a pointer to a region of data along with the size of
that region.

s2n_mem.h provides s2n_alloc(), s2n_realloc() and s2n_free() functions that may
be used to manage dynamically allocated blobs. These functions map directly
to realloc() and free() and are used only to ensure that the size of the 
memory region is consistently tracked with an s2n_blob.

## Stuffer : a buffer for stuff

The stuffer data structure included in s2n is intended to handle all
input and output to memory buffers. In addition to basic size and overflow
management, a stuffer can also perform serialisation and de-serialisation for
commonly used types and encodings.

At the core of the stuffer there are four variables being tracked which
together emulate a stream:

![Stuffer layout](s2n_stuffer_layout.png "s2n stuffer internal layout")

Data can be written to a stuffer and this will increment the write cursor.
Internally, the stuffer routines ensure that no more data can be written to the
stuffer than there is space available. Data can be read from the stuffer, and
this increments the read cursor. Attempts to read data beyond the write cursor
will fail.

There are also three types of stuffer: static stuffers which are backed by
memory provided by the caller (usually a static buffer, allocated on the
stack), alloced stuffers which are backed by realloc() but fixed in size and
growable stuffers, which are backed by realloc() but may also grow in size to
meet demand and can be resized using s2n_stuffer_resize().

Static buffers are initialized with s2n_stuffer_init(), alloced stuffers with
s2n_stuffer_alloc() and growable stuffers with s2n_stuffer_growable_alloc().
One initialized or allocated, stuffers also have a repeating life-cycle, with
calls to s2n_stuffer_wipe() providing the re-incarnation and resetting the
stuffer to its initial state (and wiping the contents).

For performance reasons it is sometimes nesseccary to operate directly on the
contents of a stuffer. s2n_stuffer_raw_read() and s2n_stuffer_raw_write() are
provided for this, s2n_stuffer_raw_read() should be called when data is being
read directly, s2n_stuffer_raw_write() should be called when data is being
inserted directly. Boundary and overflow checking will still be performed.

Both of these functions return pointers. To ensure that these pointers remain
valid, these functions both mark a stuffer as tainted. A tainted stuffer cannot
be grown or resized, to prevent any underlying call to realloc() from
invalidating the pointers. s2n_stuffer_wipe() will reset the tainted state, so
any pointers saved can not used once this has been called.

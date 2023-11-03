+++
title = 'Coding style and conventions'
date = 2023-10-27T13:42:48-07:00
weight = 40
draft = false
+++

Per our development principles, an important goal is to reduce the cognitive load required to
read, review and extend s2n-tls . Although s2n-tls is written in C, s2n-tls adopts several
patterns more common to functional programming. Though they are used in a way
that is idiomatic and shouldn't feel completely alien in C.

## High level function design

The first convention is that's s2n-tls's functions are generally quite small, no
more than a page or two at most and commonly just a few lines. Functions
have a clear input and output and are in that sense "pure" functions; for
example handling a particular TLS handshake message type takes the message
as input, and the output is connection state.

```c
/* An idiomatic s2n-tls function generally has:
 *
 *  An s2n_result return value. This is used to signal success or error.
 *  An input, often a struct.
 *  An output, often a struct.
 */
S2N_RESULT s2n_do_something(struct *some_input, struct *some_output);
```

s2n-tls functions also operate in a message passing style. For example,
a simplified version of the flow when handling a TLS client finished message
might looks like this:

![s2n-tls message passing](../../images/s2n_lambda.png "s2n-tls message passing")

each function handles a clear, well-defined piece of work, before passing on
responsibility to the next function.

The second convention of s2n-tls's functions is that functions are
split into two kinds: those that handle control flow and coordinate
other functions, and those that parse messages. For example, in the above
diagram, it might appear that the functions are calling each other directly
but we try to avoid that. Instead there is a coordinating outer function
responsible for the flow control.

A simplified version of the coordinating function would resemble:

```c
GUARD(s2n_stuffer_read(connection, input_stuffer));
GUARD(s2n_cbc_aes_decrypt(input_stuffer, output_stuffer));
GUARD(s2n_cbc_verify(output_stuffer));
```

Splitting things up this way leads to a shallower call stack, but the main
benefit is that functions can read quite declaratively. In the case of message
parsers, the function contents can read almost like schemas of the message
being parsed.

A good example file for message parsing to look at is [tls/s2n_server_finished.c](https://github.com/aws/s2n-tls/blob/main/tls/s2n_server_finished.c).
From reading the file it should be reasonably clear that a server
finished message consists just of S2N_TLS_FINISHED_LEN number of bytes, what
the next state is and so on.

As you may also see in that file, the functions for reading and writing a
particular message type are in the same file. That way all of context and
logic needed to handle that message type can be reviewed and thought about in
one place.

## Error handling and Macros

As may also be clear from the above examples, s2n-tls has some conventions for how errors are handled. Firstly, s2n-tls functions should always return `S2N_RESULT_ERROR` or `NULL` on error, and `S2N_RESULT_OK` or a valid pointer on success. s2n-tls also includes a thread local variable: s2n_errno, for indicating the cause of the error. This follows the convention set by libc (with errno), getaddrinfo (gai_errno), net-snmp (snmp_errno), and countless other libraries.

In s2n-tls, we **always** check return values. Because of that, the coding pattern:

```c
if (s2n_result_is_error(s2n_do_something(with_something_else))) {
    return S2N_RESULT_ERROR;
}
```

is so common that [utils/s2n_safety.h](https://github.com/aws/s2n-tls/blob/main/utils/s2n_safety.h) provides several macros for working with fallible functions. Notable macros include;

```c
/**
 * Ensures `x` is not an error, otherwise the function will return a `S2N_RESULT_ERROR`
 */
#define GUARD( x ) ...

/**
 * Ensures `x` is not an error, otherwise the function will return `NULL`
 */
#define GUARD_PTR( x ) ...
```

These macros should be used when calling functions you expect to succeed. Primarily these macros help save two lines that repeatedly clutter files, and secondarily they are very useful when developing and debugging code as it is easy to redefine the macro to implement a simple backtrace (even a simple printf will suffice, but a breakpoint is more usual).

If a function does fail, it should use the `BAIL(errno)` macro provided for surfacing the error to an application.
New error translations, and their human-readable translations can be defined in [error/s2n_errno.h](https://github.com/aws/s2n-tls/blob/main/error/s2n_errno.h) and [error/s2n_errno.c](https://github.com/aws/s2n-tls/blob/main/error/s2n_errno.c). When called, e.g.:

```c
BAIL(S2N_ERR_BAD_MESSAGE);
```

the macro will set s2n_errno correctly, as well as some useful debug strings, and return `S2N_RESULT_ERROR`.

### Safety checking

[utils/s2n_safety.h](https://github.com/aws/s2n-tls/blob/main/utils/s2n_safety.h) provides several more convenience macros intended to make safety and bounds checking easier. There are checked versions of memcpy (`CHECKED_MEMCPY`) and memset (`CHECKED_MEMSET`), as well as predicate testers like `ENSURE`, `ENSURE_GTE`, `ENSURE_INCLUSIVE_RANGE`, `ENSURE_EXCLUSIVE_RANGE` for performing simple comparisons in a systematic, error-handled, way.

*Note*: In general, C preprocessor Macros with embedded control flow are a bad idea, but `GUARD`, `ENSURE`, and `BAIL` are so thoroughly used throughout s2n-tls that it should be a clear and idiomatic pattern, almost forming a small domain specific language.

### Cleanup on Error

As discussed below, s2n-tls rarely allocates resources, and so has nothing to clean up on error.  For cases where functions do allocate resources which must be cleaned up, s2n-tls offers a macro:

```c
/**
 * Runs _thecleanup function on _thealloc once _thealloc went out of scope
 */
#define DEFER_CLEANUP(_thealloc, _thecleanup) ...
```

`DEFER_CLEANUP(_thealloc, _thecleanup)` is a failsafe way of ensuring that resources are cleaned up, using the ` __attribute__((cleanup())` destructor mechanism available in modern C compilers.  When the variable declared in `_thealloc` goes out of scope, the cleanup function `_thecleanup` is automatically called.  This guarantees that resources will be cleaned up, no matter how the function exits.

## Lifecycle of s2n memory

s2n states publicly that every `s2n_init()` call should be paired with an `s2n_cleanup()` call, but we also attempt to do some auto-cleanup behind the scenes because we know not every s2n-user can actually follow those steps. Unfortunately, that auto-cleanup has also caused issues because it's not very well documented and is not guaranteed to work. Here is our general philosophy behind the auto-clean behavior.

For every thread that s2n functions are called in, a small amount of thread-local memory also gets initialized. This is to ensure that our random number generator will output different numbers in different threads. This memory needs to be cleaned up per thread and users can do this themselves if they call `s2n_cleanup()` per thread. But if they forget, we utilize a pthread key that calls a destructor function that cleans up our thread-local memory when the thread closes.

An important thing to note is that a call to `s2n_cleanup()` usually does not fully clean up s2n. It only cleans up the thread-local memory. This is because we have an atexit handler that does fully clean up s2n at process-exit.
The behavior is different if the atexit handler is disabled by calling `s2n_disable_atexit()`. Then s2n is actually fully cleaned up if `s2n_cleanup()` is called on the thread that called `s2n_init()`.

## Control flow and the state machine

Branches can be a source of cognitive load, as they ask the reader to follow a path of thinking, while also remembering that there is another path to be explored. When branches are nested, they can often lead to impossible to grasp combinatorial explosions. s2n-tls tries to systematically reduce the number of branches used in the code in several ways.

Firstly, there are almost no `ifdef` calls in s2n-tls . `Ifdef` can be a particularly penalizing source of cognitive load. In addition to being a branch, they also ask the reader to mix state from two different languages (C, and the C preprocessor) and they tend to be associated with ugly rendering in IDEs and code formatters. In the few places where ifdef's are necessary, we use them in a careful way without compromising the integrity of the function. [tls/s2n_config.c](https://github.com/aws/s2n-tls/blob/main/tls/s2n_config.c) is a good example. Rather than mixing the Apple and non-Apple implementations and cluttering one function with several ifdefs, there is a complete implementation of the timer functionality for each platform. Within the POSIX implementation, an ifdef and define are used to use the most precise clock type, but in a way that does not compromise readability.

Secondly, s2n-tls generally branches in the case of failure, rather than success. So instead of creating a nest of `if`'s:

```c
if (s2n_foo() == 0) {
    if (s2n_bar() == 0) {
         if (s2n_baz() == 0) {
```

we do:

```c
GUARD(s2n_foo());
GUARD(s2n_bar());
GUARD(s2n_baz());
```

This pattern leads to a linear control flow, where the main body of a function describes everything that happens in a regular, "*happy*" case. Any deviation is usually a fatal error and we exit the function. This is safe because s2n-tls rarely allocates resources, and so has nothing to clean up on error.

This pattern also leads to extremely few `else`` clauses in the s2n-tls code base. Within s2n-tls, `else` clauses should be treated with suspicion and examined for potential eradication. Where an else clause is necessary, we try to ensure that the first if block is the most likely case. This aids readability, and also results in a more efficient compiled instruction pipeline (although good CPU branch prediction will rapidly correct any misordering).

For branches on small enumerated types, s2n-tls generally favors switch statements: though switch statements taking up more than about 25 lines of code are discouraged, and a `default:` block is mandatory.

Another technique for complexity avoidance is that the core TLS state machine within s2n-tls does not use branches and instead uses a table of function pointers (another technique borrowed from functional programming) to dispatch data to the correct handler. This is covered in more detail later in this document.

Lastly, s2n-tls studiously avoids locks. s2n-tls is designed to be thread-safe, but does so by using atomic data types in the small number of well-isolated variables that may be accessed by multiple threads.

## Code formatting and commenting

s2n-tls is written in C99. The code formatting and indentation should be relatively clear from reading some s2n-tls source files, but we also have a `.clang-format` file which we are adopting. The code format is checked by a CI job, and if clang-format finds any unformatted code the check will fail. For convenience, there is a utility script at `./codebuild/bin/clang_format_changed_files.sh` which will format all of the source files changed on a git branch.

There should be no need for comments to explain *what* s2n-tls code is doing; variables and functions should be given clear and human-readable names that make their purpose and intent intuitive. Comments explaining *why* we are doing something are encouraged. Often some context setting is necessary; a reference to an RFC, or a reminder of some critical state that is hard to work directly into the immediate code in a natural way. All comments should be written using C syntax `/* */` and **avoid** C++ comments `//` even though C99 compilers allow `//`.

Every source code file must include a copy of the Apache Software License 2.0, as well as a correct copyright notification. The year of copyright should be the year in which the file was first created.

There is also a brief set of other coding conventions:

* s2n-tls uses explicitly sized primitives where possible. E.g. uint8_t, uint32_t.
* In general, s2n-tls uses unsigned ints for sizes, as TLS/SSL do the same.
* Any structures exposed to application authors must be opaque: s2n-tls manages the memory allocation and de-allocation.
* Variables are declared closest to their first point of use, to maximize context around the typing.
* Duplication of logic is discouraged
* 4 spaces, no tabs
* Assuming a terminal that is 120 characters wide is ok
* Control structures should always include curly braces (even if only one line)

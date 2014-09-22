# Development guide for SignalToNoise

If you are interested in working on, or are curious about, the internals of
SignalToNoise it is helpful to understand some common conventions that are used
throughout the code.

## Readability and short functions

One of the goals of the s2n code layout is to reduce the cognitive load on the
programmer required to  write, review and extend s2n functionality. s2n is
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

All s2n functions return -1 or NULL on error. Additionally s2n functions have a
convention of taking a "const char **err" parameter as their last argument.  On
error, functions should point the *err pointer at a string explaining the error
encountered.

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
be used to manage dynamically allocated blobs.

## Stuffer : a buffer for stuff

The stuffer data structure included in SignalToNoise is intended to handle all
input and output to memory buffers. In addition to basic size and overflow
management, a stuffer can also perform serialisation and de-serialisation for
commonly used types and encodings.

At the core of the stuffer there are four variables being tracked which
together emulate a stream:

                             data_available()      space_remaining()
                                  |                       |
                      /-----------------------\/--------------------\
    -----------------------------------------------------------------
    |   |   |   |   | R |   |   |   |   |   | W |   |   |   |   |   |
    -----------------------------------------------------------------
    ^                 ^                       ^                     ^
    data          read cursor            write cursor          data + size

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

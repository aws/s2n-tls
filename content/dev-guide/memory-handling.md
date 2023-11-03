+++
title = 'Memory handling'
date = 2023-10-27T13:45:16-07:00
weight = 55
draft = false
+++

# A tour of s2n-tls memory handling: blobs and stuffers

C has a history of issues around memory and buffer handling. To avoid problems in this area, s2n-tls does not use C string functions or standard buffer manipulation patterns. Instead memory regions are tracked explicitly, with `s2n_blob` structures, and buffers are re-oriented as streams with `s2n_stuffer` structures.

## s2n_blob: keeping track of memory ranges

`s2n_blob` is a very simple data structure:

```c
struct s2n_blob {
    uint8_t *data;
    uint32_t size;
};
```

Functions that handle memory ranges are expected to at least use blobs (stuffers are better though, as we'll see). A blob can be initialized with an existing memory buffer using **s2n_blob_init**, but  [utils/s2n_mem.h](https://github.com/aws/s2n-tls/blob/main/utils/s2n_mem.h) also defines routines for dynamically allocated blobs. For handling user data, we prefer the latter, as s2n-tls prevents the memory regions from being swapped to disk and from showing up in core files (where supported).

## s2n_stuffer: a streaming buffer

The stuffer data structure included in s2n-tls is intended to handle all protocol level
input and output to memory buffers and is the real work-horse of s2n-tls . At its core
a stuffer is a blob and two cursors:

```c
struct s2n_stuffer {
    struct s2n_blob blob;
    uint32_t read_cursor;
    uint32_t write_cursor;
    ...
};
```

This layout that makes it possible to implement a stream:

![Stuffer layout](images/s2n_stuffer_layout.png "s2n-tls stuffer internal layout")

All access to/from the stuffer goes "through" `s2n_stuffer_` functions. For example, we can write with **s2n_stuffer_write()**, and when we do the write cursor is incremented to the new position. We can read with **s2n_stuffer_read()**, and of course we can only read data as far as the write cursor (which is always at or ahead of the read cursor). To protect user data, when we read data out of the stuffer, we wipe the copy of the data within the local stuffer memory. We also ensure that it's only possible to read as much data as is in the stuffer.

A stuffer can be initialized directly from a blob, which makes it fixed in size, or it can be allocated dynamically. In the latter case, we can also choose to make the stuffer growable (by using **s2n_stuffer_growable_alloc** instead of **s2n_stuffer_alloc**). If a stuffer is growable then attempting to write past the end of the current blob will result in the blob being extended (by at least 1K at a time) to fit the data.

To further encourage stream-oriented programming, the stuffer is also the place where all marshaling and de-marshaling happens. For example, you can read and write ints directly to a stuffer:

```c
/* Read and write integers in network order */
int s2n_stuffer_read_uint8(struct s2n_stuffer *stuffer, uint8_t *u);
int s2n_stuffer_read_uint16(struct s2n_stuffer *stuffer, uint16_t *u);
int s2n_stuffer_read_uint24(struct s2n_stuffer *stuffer, uint32_t *u);
int s2n_stuffer_read_uint32(struct s2n_stuffer *stuffer, uint32_t *u);
int s2n_stuffer_read_uint64(struct s2n_stuffer *stuffer, uint64_t *u);
int s2n_stuffer_write_uint8(struct s2n_stuffer *stuffer, uint8_t u);
int s2n_stuffer_write_uint16(struct s2n_stuffer *stuffer, uint16_t u);
int s2n_stuffer_write_uint24(struct s2n_stuffer *stuffer, uint32_t u);
int s2n_stuffer_write_uint32(struct s2n_stuffer *stuffer, uint32_t u);
int s2n_stuffer_write_uint64(struct s2n_stuffer *stuffer, uint64_t u);
```

and there are other utility functions for handling base64 encoding to and from a stuffer, or text manipulation - like tokenization. The idea is to implement basic serializing just once, rather than spread out and duplicated across the message parsers, and to maximize the declarative nature of the I/O. For example, this code parses a TLS record header:

```c
GUARD(s2n_stuffer_read_uint8(in, &message_type));
GUARD(s2n_stuffer_read_uint8(in, &protocol_major_version));
GUARD(s2n_stuffer_read_uint8(in, &protocol_minor_version));
GUARD(s2n_stuffer_read_uint16(in, &record_size));
```

This pattern should make it very clear what the message format is, where the contents are being stored, and that we're handling things in a safe way.

There are times when we must interact with C functions from other libraries; for example, when handling encryption and decryption. In these cases, it is usually necessary to provide access to "raw" pointers into stuffers. s2n-tls provides two functions for this:

```c
void *s2n_stuffer_raw_write(struct s2n_stuffer *stuffer, uint32_t data_len);
void *s2n_stuffer_raw_read(struct s2n_stuffer *stuffer, uint32_t data_len);
```

the first function returns a pointer to the existing location of the write cursor, and then increments the write cursor by `data_len`, so an external function is free to write to the pointer, as long as it only writes `data_len` bytes.
The second function does the same thing, except that it increments the read cursor.
Use of these functions is discouraged and should only be done when necessary for compatibility.

One problem with returning raw pointers is that a pointer can become stale if the stuffer is later resized. Growable stuffers are resized using realloc(), which is free to copy and re-address memory. This could leave the original pointer location dangling, potentially leading to an invalid access. To prevent this, stuffers have a life-cycle and can be tainted, which prevents them from being resized within their present life-cycle.

Internally stuffers track 4 pieces of state:

```c
uint32_t     high_water_mark;
unsigned int alloced:1;
unsigned int growable:1;
unsigned int tainted:1;
```

The `high_water_mark` tracks the furthermost byte which has been written but not yet wiped.
Note that this may be past the `write_cursor` if `s2n_stuffer_rewrite()` has been called.
Explicitly tracking the `high_water_mark` allows us to track the bytes which need to be wiped, and helps avoids needless zeroing of memory.
The next two bits of state track whether a stuffer was dynamically allocated (and so should be free'd later) and whether or not it is growable.
`tainted` is set to 1 whenever the raw access functions are called.
If a stuffer is currently tainted then it can not be resized and it becomes ungrowable.
This is reset when a stuffer is explicitly wiped, which begins the life-cycle anew.
So any pointers returned by the raw access functions are legal only until `s2n_stuffer_wipe()` is called.
The end result is that this kind of pattern is legal:

```c
GUARD(s2n_stuffer_growable_alloc(&in, 1500));
GUARD(s2n_stuffer_write(&in, &fifteen_hundred_bytes_blob));
uint8_t * ptr = s2n_stuffer_raw_read(&in, 1500);
```

but attempting to write more data would not be legal:

```c
GUARD(s2n_stuffer_growable_alloc(&in, 1500));
GUARD(s2n_stuffer_write(&in, &fifteen_hundred_bytes_blob));
uint8_t * ptr = s2n_stuffer_raw_read(&in, 1500);

/* This write will fail, the stuffer is no longer growable, as a raw
 * pointer was taken */
GUARD(s2n_stuffer_write(&in, &some_more_data_blob);

/* Stuffer life cycle is now complete, reset everything and wipe */
GUARD(s2n_stuffer_wipe(&in));
```

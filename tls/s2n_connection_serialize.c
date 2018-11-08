#include "s2n_connection.h"

#include "utils/s2n_safety.h"
#define static_assert(expr, msg) _Static_assert(expr, msg)
#define alignof _Alignof

static int blob_extract(struct s2n_blob* this, const uint8_t** reader)
{
  GUARD(s2n_alloc(this, this->allocated));
  memcpy_check(this->data, *reader, this->size);
  *reader += this->size;
  return 0;
}
static int blob_write(struct s2n_blob* this, uint8_t** writer, size_t* total_bytes)
{
  memcpy_check(*writer, this->data, this->size);
  *writer += this->size;
  *total_bytes += this->size;
  return 0;
}
static int reader_blob_check(const struct s2n_blob* blob,
                             const uint8_t* reader, const uint8_t* reader_end)
{
  notnull_check(blob);
  if (reader + blob->size > reader_end) {
    return -1;
  }
  return 0;
}

ssize_t s2n_conn_serialize_to(struct s2n_connection* conn,
                              void* addr, size_t size)
{
  notnull_check(addr);
  // must have at least size of connection bytes
  gte_check(size, sizeof(struct s2n_connection));
  // wholesale copy the connection
  memcpy_check(addr, conn, sizeof(struct s2n_connection));
  // sanitize the destination
  struct s2n_connection* dst = (struct s2n_connection*) addr;
  // set to NULL for initial, otherwise its secure
  if (conn->client == &conn->initial) dst->client = NULL;
  if (conn->server == &conn->initial) dst->server = NULL;
  
  // now done with connection, subtract size
  size_t total_bytes = sizeof(struct s2n_connection);
  size -= sizeof(struct s2n_connection);
  
  // the writer points to the end of the connection struct
  // NOTE that since the struct is well aligned, so is the writer
  uint8_t* writer = &((uint8_t*) addr)[total_bytes];
  
  // start serializing stuffers and blobs
  GUARD(blob_write(&conn->in.blob, &writer, &total_bytes));
  GUARD(blob_write(&conn->out.blob, &writer, &total_bytes));

  return total_bytes;
}

struct s2n_connection* s2n_conn_deserialize_from(
                          struct s2n_config* config,
                          const void*  addr,
                          const size_t size)
{
  // if there is not enough room for a connection, exit immediately
  if (size < sizeof(struct s2n_connection)) return NULL;
  
  // pointers to start and end of serialized area
  const uint8_t* reader_begin = (const uint8_t*) addr;
  const uint8_t* reader_end   = &reader_begin[size];
  // iterator to read from
  const uint8_t* reader       = &reader_begin[0];
  
  struct s2n_blob blob = {0};
  struct s2n_connection *conn;

  GUARD_PTR(s2n_alloc(&blob, sizeof(struct s2n_connection)));
  GUARD_PTR(s2n_blob_zero(&blob));
  conn = (struct s2n_connection *)(void *)blob.data;
  
  // wholesale copy from reader into the connection
  memcpy_check_ptr(conn, reader, sizeof(struct s2n_connection));
  reader += sizeof(struct s2n_connection);
  
  // set the config correctly and set some expected defaults
  conn->config = config;
  conn->cipher_pref_override = NULL;
  conn->context = NULL;
  conn->send    = NULL;
  conn->recv    = NULL;
  conn->send_io_context = NULL;
  conn->recv_io_context = NULL;
  
  // restore some connection-owned blob data pointers
  conn->header_in.blob.data = conn->header_in_data;
  conn->alert_in.blob.data = conn->alert_in_data;
  conn->reader_alert_out.blob.data = conn->reader_alert_out_data;
  conn->writer_alert_out.blob.data = conn->writer_alert_out_data;
  conn->client_ticket_to_decrypt.blob.data = conn->ticket_ext_data;
  
  // crypto-stuff
  conn->client = (conn->client == NULL) ? &conn->initial : &conn->secure;
  conn->server = (conn->server == NULL) ? &conn->initial : &conn->secure;
  
  // TODO: we will have to store and restore this
  GUARD_PTR(s2n_stuffer_growable_alloc(&conn->handshake.io, 0));
  // TODO: we will have to store and restore this
  GUARD_PTR(s2n_stuffer_growable_alloc(&conn->client_hello.raw_message, 0));
  
  // extract data-in blob
  GUARD_PTR(reader_blob_check(&conn->in.blob, reader, reader_end));
  GUARD_PTR(blob_extract(&conn->in.blob, &reader));
  // extract data-out blob
  GUARD_PTR(reader_blob_check(&conn->out.blob, reader, reader_end));
  GUARD_PTR(blob_extract(&conn->out.blob, &reader));
  
  // warn on not consuming all bytes
  if (reader != reader_end) {
    fprintf(stderr,
    "WARNING: s2n_connection did not deserialize all bytes (%zu vs %zu)\n",
    reader - reader_begin, reader_end - reader_begin);
  }
  return conn;
}

#include "s2n_connection.h"

#include "utils/s2n_safety.h"
#define static_assert(expr, msg) _Static_assert(expr, msg)
#define alignof _Alignof

struct serialized_blob
{
  uint32_t size;
  uint32_t allocated;
  unsigned int mlocked:1;
} __attribute__((aligned(alignof(uint8_t*))));
static_assert(sizeof(struct serialized_blob)
           == sizeof(struct s2n_blob) - sizeof(void*),
              "Should be same as a s2n_blob minus the data pointer");

struct serialized_stuffer
{
  struct serialized_blob blob;
  
  /* Cursors to the current read/write position in the s2n_stuffer */
  uint32_t read_cursor;
  uint32_t write_cursor;

  /* The total size of the data segment */
  /* Has the stuffer been wiped? */
  unsigned int wiped:1;

  /* Was this stuffer alloc()'d ? */
  unsigned int alloced:1;

  /* Is this stuffer growable? */
  unsigned int growable:1;

  /* A growable stuffer can also be temporarily tainted */
  unsigned int tainted:1;
} __attribute__((aligned(alignof(uint8_t*))));
static_assert(sizeof(struct serialized_stuffer)
           == sizeof(struct s2n_stuffer) - sizeof(void*),
              "Should be same as a s2n_stuffer minus the data pointer");

struct s2n_blob blob_extract(struct serialized_blob* this,
                             uint8_t* data)
{
  struct s2n_blob blob;
  blob.data = data;
  blob.size      = this->size;
  blob.allocated = this->allocated;
  blob.mlocked   = this->mlocked;
  return blob;
}

struct s2n_stuffer stuffer_extract(struct serialized_stuffer* this,
                                   uint8_t* data)
{
  struct s2n_stuffer stuffer;
  stuffer.blob = blob_extract(&this->blob, data);
  stuffer.read_cursor = this->read_cursor;
  stuffer.write_cursor = this->write_cursor;
  stuffer.wiped    = this->wiped;
  stuffer.alloced  = this->alloced;
  stuffer.growable = this->growable;
  stuffer.tainted  = this->tainted;
  return stuffer;
}

struct serialized_connection
{
  uint8_t  corked_io : 1;
  uint8_t  client_session_resumed : 1;
  uint8_t  close_notify_queued : 1;
  uint8_t  secure_renegotiation : 1;
  uint8_t  ipv6 : 1;
  s2n_mode mode;
  s2n_blinding blinding;
  struct s2n_timer write_timer; /* use assignment */
  uint64_t last_write_elapsed;
  uint64_t delay;
  uint8_t  session_id[S2N_TLS_SESSION_ID_MAX_LEN];
  uint8_t  session_id_len;
  uint8_t  client_hello_version;
  uint8_t  client_protocol_version;
  uint8_t  server_protocol_version;
  uint8_t  actual_protocol_version;
  uint8_t  actual_protocol_version_established;
  /* Our crypto parameters */
  struct s2n_crypto_parameters initial;
  struct s2n_crypto_parameters secure;

  /* Which set is the client/server actually using? */
  uint8_t secure_selected;

  /* The PRF needs some storage elements to work with */
  struct s2n_prf_working_space prf_space;

  uint8_t client_cert_auth_type_overridden;
  s2n_cert_auth_type client_cert_auth_type;

  uint8_t header_in_data[S2N_TLS_RECORD_HEADER_LENGTH];
  struct s2n_stuffer header_in;
  struct s2n_stuffer in;
  struct s2n_stuffer out;
  enum { ENCRYPTED, PLAINTEXT } in_status;

  ssize_t current_user_data_consumed;

  uint8_t alert_in_data[S2N_ALERT_LENGTH];
  struct s2n_stuffer alert_in;

  uint8_t reader_alert_out_data[S2N_ALERT_LENGTH];
  uint8_t writer_alert_out_data[S2N_ALERT_LENGTH];
  struct s2n_stuffer reader_alert_out;
  struct s2n_stuffer writer_alert_out;

  /* Contains parameters needed during the handshake phase */
  struct s2n_handshake_parameters handshake_params;

  /* Our handshake state machine */
  struct s2n_handshake handshake;

  uint16_t max_outgoing_fragment_length;

  uint32_t dynamic_record_resize_threshold; /* disabled */
  uint16_t dynamic_record_timeout_threshold;

  /* number of bytes consumed during application activity */
  uint64_t active_application_bytes_consumed;

  /* Negotiated TLS extension Maximum Fragment Length code */
  uint8_t mfl_code;

  /* Keep some accounting on each connection */
  uint64_t wire_bytes_in;
  uint64_t wire_bytes_out;

  sig_atomic_t closing;
  sig_atomic_t closed;

  /* TLS extension data */
  char server_name[256];

  /* The application protocol decided upon during the client hello.
   * If ALPN is being used, then:
   * In server mode, this will be set by the time client_hello_cb is invoked.
   * In client mode, this will be set after is_handshake_complete(connection) is true.
   */
  char application_protocol[256];

  /* OCSP stapling response data */
  s2n_status_request_type status_type;
  struct s2n_blob status_response;

  /* Certificate Transparency response data */
  s2n_ct_support_level ct_level_requested;
  struct s2n_blob ct_response;

  struct s2n_client_hello client_hello;

  struct s2n_x509_validator x509_validator;

  /* Session ticket data */
  s2n_session_ticket_status session_ticket_status;
  struct s2n_blob client_ticket;
  uint32_t ticket_lifetime_hint;

  /* Session ticket extension from client to attempt to decrypt as the server. */
  uint8_t ticket_ext_data[S2N_TICKET_SIZE_IN_BYTES];
  struct s2n_stuffer client_ticket_to_decrypt;

  /* application protocols overridden */
  struct s2n_blob application_protocols_overridden;
};

size_t s2n_conn_serialize_to(struct s2n_connection* conn, void* addr)
{
  struct serialized_connection* writer;
  notnull_check(writer = (struct serialized_connection*) addr);
  writer->max_outgoing_fragment_length = conn->max_outgoing_fragment_length;
  
  return sizeof(struct s2n_connection);
}

struct s2n_connection* s2n_conn_serialize_from(void* addr)
{
  struct s2n_blob blob = {0};
  struct s2n_connection *conn;

  GUARD_PTR(s2n_alloc(&blob, sizeof(struct s2n_connection)));
  GUARD_PTR(s2n_blob_zero(&blob));
  conn = (struct s2n_connection *)(void *)blob.data;
  
  return conn;
}

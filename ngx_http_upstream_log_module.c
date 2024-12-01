
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Hanada
 */


#include "ngx_http_upstream_log_module.h"

#if (NGX_ZLIB)
#include <zlib.h>
#endif


#define NGX_HTTP_UPSTREAM_LOG_ESCAPE_DEFAULT          0
#define NGX_HTTP_UPSTREAM_LOG_ESCAPE_JSON             1
#define NGX_HTTP_UPSTREAM_LOG_ESCAPE_NONE             2

#define NGX_HTTP_UPSTREAM_LOG_START_TS                10
#if (NGX_HTTP_SSL)
#define NGX_HTTP_UPSTREAM_LOG_SSL_START_TS            11
#endif
#define NGX_HTTP_UPSTREAM_LOG_SEND_START_TS           12
#define NGX_HTTP_UPSTREAM_LOG_SEND_END_TS             13
#define NGX_HTTP_UPSTREAM_LOG_HEADER_TS               14
#define NGX_HTTP_UPSTREAM_LOG_END_TS                  15

#define NGX_HTTP_UPSTREAM_LOG_CONNECT_TIME            20
#define NGX_HTTP_UPSTREAM_LOG_TRANSPORT_CONNECT_TIME  21
#if (NGX_HTTP_SSL)
#define NGX_HTTP_UPSTREAM_LOG_SSL_TIME                22
#endif
#define NGX_HTTP_UPSTREAM_LOG_SEND_TIME               23
#define NGX_HTTP_UPSTREAM_LOG_READ_TIME               24
#define NGX_HTTP_UPSTREAM_LOG_HEADER_TIME             25
#define NGX_HTTP_UPSTREAM_LOG_RESPONSE_TIME           26

#define NGX_HTTP_UPSTREAM_LOG_RESPONSE_LENGTH         30
#define NGX_HTTP_UPSTREAM_LOG_BYTES_RECEIVED          31
#define NGX_HTTP_UPSTREAM_LOG_BYTES_SENT              32


 /*
 * Types defined in this file was completely copy from ngx_http_log_module, 
 * if them changes in the future, please update codes here.
 */

typedef struct ngx_http_log_op_s  ngx_http_log_op_t;

typedef u_char *(*ngx_http_log_op_run_pt) (ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);

typedef size_t (*ngx_http_log_op_getlen_pt) (ngx_http_request_t *r,
    uintptr_t data);


struct ngx_http_log_op_s {
    size_t                      len;
    ngx_http_log_op_getlen_pt   getlen;
    ngx_http_log_op_run_pt      run;
    uintptr_t                   data;
};


typedef struct {
    ngx_str_t                   name;
    ngx_array_t                *flushes;
    ngx_array_t                *ops;        /* array of ngx_http_log_op_t */
} ngx_http_log_fmt_t;


typedef struct {
    u_char                     *start;
    u_char                     *pos;
    u_char                     *last;

    ngx_event_t                *event;
    ngx_msec_t                  flush;
    ngx_int_t                   gzip;
} ngx_http_log_buf_t;


typedef struct {
    ngx_array_t                *lengths;
    ngx_array_t                *values;
} ngx_http_log_script_t;


typedef struct {
    ngx_open_file_t            *file;
    ngx_http_log_script_t      *script;
    time_t                      disk_full_time;
    time_t                      error_log_time;
    ngx_syslog_peer_t          *syslog_peer;
    ngx_http_log_fmt_t         *format;
    ngx_http_complex_value_t   *filter;
} ngx_http_log_t;


typedef struct {
    ngx_array_t                *logs;       /* array of ngx_http_log_t */

    ngx_open_file_cache_t      *open_file_cache;
    time_t                      open_file_cache_valid;
    ngx_uint_t                  open_file_cache_min_uses;

    ngx_flag_t                  escape_non_ascii;

    ngx_uint_t                  off;        /* unsigned  off:1 */
} ngx_http_log_loc_conf_t;


/* Only this struct is defined by this module */
typedef struct {
    ngx_array_t                *logs;       /* array of ngx_http_log_t */

    ngx_uint_t                  off;        /* unsigned  off:1 */
} ngx_http_upstream_log_loc_conf_t;


extern ngx_module_t          ngx_http_log_module;


static void ngx_http_upstream_log_write(ngx_http_request_t *r, ngx_http_log_t *log,
    u_char *buf, size_t len);
static ssize_t ngx_http_upstream_log_script_write(ngx_http_request_t *r,
    ngx_http_log_script_t *script, u_char **name, u_char *buf, size_t len);

#if (NGX_ZLIB)
static ssize_t ngx_http_upstream_log_gzip(ngx_fd_t fd, u_char *buf, size_t len,
    ngx_int_t level, ngx_log_t *log);

static void *ngx_http_upstream_log_gzip_alloc(void *opaque, u_int items, u_int size);
static void ngx_http_upstream_log_gzip_free(void *opaque, void *address);
#endif

static void ngx_http_upstream_log_flush(ngx_open_file_t *file, ngx_log_t *log);
static void ngx_http_upstream_log_flush_handler(ngx_event_t *ev);


static ngx_int_t ngx_http_upstream_log_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_upstream_log_method_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upstream_log_scheme_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upstream_log_uri_variable( ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upstream_log_addr_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upstream_log_status_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upstream_log_multi_ts_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upstream_log_single_ts_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upstream_log_multi_time_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upstream_log_single_time_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
#if 0
static ngx_int_t ngx_http_upstream_log_multi_length_variable(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
#endif
static ngx_int_t ngx_http_upstream_log_single_length_variable(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static void *ngx_http_upstream_log_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_log_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_upstream_log_set_log(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t ngx_http_upstream_log_commands[] = {

    { ngx_string("upstream_log"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_HTTP_LMT_CONF|NGX_CONF_1MORE,
      ngx_http_upstream_log_set_log,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },


    ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_log_module_ctx = {
    ngx_http_upstream_log_add_variables,            /* preconfiguration */
    NULL,                                           /* postconfiguration */

    NULL,                                           /* create main configuration */
    NULL,                                           /* init main configuration */

    NULL,                                           /* create server configuration */
    NULL,                                           /* merge server configuration */

    ngx_http_upstream_log_create_loc_conf,          /* create location configuration */
    ngx_http_upstream_log_merge_loc_conf            /* merge location configuration */
};


ngx_module_t ngx_http_upstream_log_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_log_module_ctx,              /* module context */
    ngx_http_upstream_log_commands,                 /* module directives */
    NGX_HTTP_MODULE,                                /* module type */
    NULL,                                           /* init master */
    NULL,                                           /* init module */
    NULL,                                           /* init process */
    NULL,                                           /* init thread */
    NULL,                                           /* exit thread */
    NULL,                                           /* exit process */
    NULL,                                           /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_upstream_log_vars[] = {

    { ngx_string("upstream_method"), NULL,
      ngx_http_upstream_log_method_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_scheme"), NULL,
      ngx_http_upstream_log_scheme_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_uri"), NULL,
      ngx_http_upstream_log_uri_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_last_addr"), NULL,
      ngx_http_upstream_log_addr_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_last_status"), NULL,
      ngx_http_upstream_log_status_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_start_ts"), NULL,
      ngx_http_upstream_log_multi_ts_variable,
      NGX_HTTP_UPSTREAM_LOG_START_TS,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_last_start_ts"), NULL,
      ngx_http_upstream_log_single_ts_variable,
      NGX_HTTP_UPSTREAM_LOG_START_TS,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

#if (NGX_HTTP_SSL)

    { ngx_string("upstream_ssl_start_ts"), NULL,
      ngx_http_upstream_log_multi_ts_variable,
      NGX_HTTP_UPSTREAM_LOG_SSL_START_TS,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_last_ssl_start_ts"), NULL,
      ngx_http_upstream_log_single_ts_variable,
      NGX_HTTP_UPSTREAM_LOG_SSL_START_TS,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

#endif

    { ngx_string("upstream_send_start_ts"), NULL,
      ngx_http_upstream_log_multi_ts_variable,
      NGX_HTTP_UPSTREAM_LOG_SEND_START_TS,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_last_send_start_ts"), NULL,
      ngx_http_upstream_log_single_ts_variable,
      NGX_HTTP_UPSTREAM_LOG_SEND_START_TS,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_send_end_ts"), NULL,
      ngx_http_upstream_log_multi_ts_variable,
      NGX_HTTP_UPSTREAM_LOG_SEND_END_TS,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_last_send_end_ts"), NULL,
      ngx_http_upstream_log_single_ts_variable,
      NGX_HTTP_UPSTREAM_LOG_SEND_END_TS,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_header_ts"), NULL,
      ngx_http_upstream_log_multi_ts_variable,
      NGX_HTTP_UPSTREAM_LOG_HEADER_TS,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_last_header_ts"), NULL,
      ngx_http_upstream_log_single_ts_variable,
      NGX_HTTP_UPSTREAM_LOG_HEADER_TS,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_end_ts"), NULL,
      ngx_http_upstream_log_multi_ts_variable,
      NGX_HTTP_UPSTREAM_LOG_END_TS,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_last_end_ts"), NULL,
      ngx_http_upstream_log_single_ts_variable,
      NGX_HTTP_UPSTREAM_LOG_END_TS,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

#if 0
    { ngx_string("upstream_connect_time"), NULL,
      ngx_http_upstream_log_multi_time_variable,
      NGX_HTTP_UPSTREAM_LOG_CONNECT_TIME,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },
#endif

    { ngx_string("upstream_last_connect_time"), NULL,
      ngx_http_upstream_log_single_time_variable,
      NGX_HTTP_UPSTREAM_LOG_CONNECT_TIME,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_transport_connect_time"), NULL,
      ngx_http_upstream_log_multi_time_variable,
      NGX_HTTP_UPSTREAM_LOG_TRANSPORT_CONNECT_TIME,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_last_transport_connect_time"), NULL,
      ngx_http_upstream_log_single_time_variable,
      NGX_HTTP_UPSTREAM_LOG_TRANSPORT_CONNECT_TIME,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

#if (NGX_HTTP_SSL)
    { ngx_string("upstream_ssl_time"), NULL,
      ngx_http_upstream_log_multi_time_variable,
      NGX_HTTP_UPSTREAM_LOG_SSL_TIME,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_last_ssl_time"), NULL,
      ngx_http_upstream_log_single_time_variable,
      NGX_HTTP_UPSTREAM_LOG_SSL_TIME,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },
#endif

    { ngx_string("upstream_send_time"), NULL,
      ngx_http_upstream_log_multi_time_variable,
      NGX_HTTP_UPSTREAM_LOG_SEND_TIME,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_last_send_time"), NULL,
      ngx_http_upstream_log_single_time_variable,
      NGX_HTTP_UPSTREAM_LOG_SEND_TIME,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_read_time"), NULL,
      ngx_http_upstream_log_multi_time_variable,
      NGX_HTTP_UPSTREAM_LOG_READ_TIME,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_last_read_time"), NULL,
      ngx_http_upstream_log_single_time_variable,
      NGX_HTTP_UPSTREAM_LOG_READ_TIME,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

#if 0
    { ngx_string("upstream_header_time"), NULL,
      ngx_http_upstream_log_multi_time_variable,
      NGX_HTTP_UPSTREAM_LOG_HEADER_TIME,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },
#endif

    { ngx_string("upstream_last_header_time"), NULL,
      ngx_http_upstream_log_single_time_variable,
      NGX_HTTP_UPSTREAM_LOG_HEADER_TIME,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

#if 0
    { ngx_string("upstream_response_time"), NULL,
      ngx_http_upstream_log_multi_time_variable,
      NGX_HTTP_UPSTREAM_LOG_RESPONSE_TIME,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },
#endif

    { ngx_string("upstream_last_response_time"), NULL,
      ngx_http_upstream_log_single_time_variable,
      NGX_HTTP_UPSTREAM_LOG_RESPONSE_TIME,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

#if 0
    { ngx_string("upstream_response_length"), NULL,
      ngx_http_upstream_log_multi_length_variable,
      NGX_HTTP_UPSTREAM_LOG_RESPONSE_LENGTH,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },
#endif

    { ngx_string("upstream_last_response_length"), NULL,
      ngx_http_upstream_log_single_length_variable,
      NGX_HTTP_UPSTREAM_LOG_RESPONSE_LENGTH,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

#if 0
    { ngx_string("upstream_bytes_received"), NULL,
      ngx_http_upstream_log_multi_length_variable,
      NGX_HTTP_UPSTREAM_LOG_BYTES_RECEIVED,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },
#endif

    { ngx_string("upstream_last_bytes_received"), NULL,
      ngx_http_upstream_log_single_length_variable,
      NGX_HTTP_UPSTREAM_LOG_BYTES_RECEIVED,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

#if 0
    { ngx_string("upstream_bytes_sent"), NULL,
      ngx_http_upstream_log_multi_length_variable,
      NGX_HTTP_UPSTREAM_LOG_BYTES_SENT,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },
#endif

    { ngx_string("upstream_last_bytes_sent"), NULL,
      ngx_http_upstream_log_single_length_variable,
      NGX_HTTP_UPSTREAM_LOG_BYTES_SENT,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

      ngx_http_null_variable
};


static ngx_str_t  ngx_http_upstream_log = ngx_string(NGX_HTTP_LOG_PATH);


ngx_int_t ngx_http_upstream_log_handler(ngx_http_request_t *r) {
    u_char                            *line, *p;
    size_t                             len, size;
    ssize_t                            n;
    ngx_str_t                          val;
    ngx_uint_t                         i, l;
    ngx_http_log_t                    *log;
    ngx_http_log_op_t                 *op;
    ngx_http_log_buf_t                *buffer;
    ngx_http_upstream_log_loc_conf_t  *ulcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream log handler");

    ulcf = ngx_http_get_module_loc_conf(r, ngx_http_upstream_log_module);

    if (ulcf->off) {
        return NGX_OK;
    }

    log = ulcf->logs->elts;
    for (l = 0; l < ulcf->logs->nelts; l++) {

        if (log[l].filter) {
            if (ngx_http_complex_value(r, log[l].filter, &val) != NGX_OK) {
                return NGX_ERROR;
            }

            if (val.len == 0 || (val.len == 1 && val.data[0] == '0')) {
                continue;
            }
        }

        if (ngx_time() == log[l].disk_full_time) {

            /*
             * on FreeBSD writing to a full filesystem with enabled softupdates
             * may block process for much longer time than writing to non-full
             * filesystem, so we skip writing to a log for one second
             */

            continue;
        }

        ngx_http_script_flush_no_cacheable_variables(r, log[l].format->flushes);

        len = 0;
        op = log[l].format->ops->elts;
        for (i = 0; i < log[l].format->ops->nelts; i++) {
            if (op[i].len == 0) {
                len += op[i].getlen(r, op[i].data);

            } else {
                len += op[i].len;
            }
        }

        if (log[l].syslog_peer) {

            /* length of syslog's PRI and HEADER message parts */
            len += sizeof("<255>Jan 01 00:00:00 ") - 1
                   + ngx_cycle->hostname.len + 1
                   + log[l].syslog_peer->tag.len + 2;

            goto alloc_line;
        }

        len += NGX_LINEFEED_SIZE;

        buffer = log[l].file ? log[l].file->data : NULL;

        if (buffer) {

            if (len > (size_t) (buffer->last - buffer->pos)) {

                ngx_http_upstream_log_write(r, &log[l], buffer->start,
                                   buffer->pos - buffer->start);

                buffer->pos = buffer->start;
            }

            if (len <= (size_t) (buffer->last - buffer->pos)) {

                p = buffer->pos;

                if (buffer->event && p == buffer->start) {
                    ngx_add_timer(buffer->event, buffer->flush);
                }

                for (i = 0; i < log[l].format->ops->nelts; i++) {
                    p = op[i].run(r, p, &op[i]);
                }

                ngx_linefeed(p);

                buffer->pos = p;

                continue;
            }

            if (buffer->event && buffer->event->timer_set) {
                ngx_del_timer(buffer->event);
            }
        }

    alloc_line:

        line = ngx_pnalloc(r->pool, len);
        if (line == NULL) {
            return NGX_ERROR;
        }

        p = line;

        if (log[l].syslog_peer) {
            p = ngx_syslog_add_header(log[l].syslog_peer, line);
        }

        for (i = 0; i < log[l].format->ops->nelts; i++) {
            p = op[i].run(r, p, &op[i]);
        }

        if (log[l].syslog_peer) {

            size = p - line;

            n = ngx_syslog_send(log[l].syslog_peer, line, size);

            if (n < 0) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "send() to syslog failed");

            } else if ((size_t) n != size) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "send() to syslog has written only %z of %uz",
                              n, size);
            }

            continue;
        }

        ngx_linefeed(p);

        ngx_http_upstream_log_write(r, &log[l], line, p - line);
    }

    return NGX_OK;
}


static void
ngx_http_upstream_log_write(ngx_http_request_t *r, ngx_http_log_t *log,
    u_char *buf, size_t len)
{
    u_char              *name;
    time_t               now;
    ssize_t              n;
    ngx_err_t            err;
#if (NGX_ZLIB)
    ngx_http_log_buf_t  *buffer;
#endif

    if (log->script == NULL) {
        name = log->file->name.data;

#if (NGX_ZLIB)
        buffer = log->file->data;

        if (buffer && buffer->gzip) {
            n = ngx_http_upstream_log_gzip(log->file->fd, buf, len, buffer->gzip,
                                  r->connection->log);
        } else {
            n = ngx_write_fd(log->file->fd, buf, len);
        }
#else
        n = ngx_write_fd(log->file->fd, buf, len);
#endif

    } else {
        name = NULL;
        n = ngx_http_upstream_log_script_write(r, log->script, &name, buf, len);
    }

    if (n == (ssize_t) len) {
        return;
    }

    now = ngx_time();

    if (n == -1) {
        err = ngx_errno;

        if (err == NGX_ENOSPC) {
            log->disk_full_time = now;
        }

        if (now - log->error_log_time > 59) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, err,
                          ngx_write_fd_n " to \"%s\" failed", name);

            log->error_log_time = now;
        }

        return;
    }

    if (now - log->error_log_time > 59) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      ngx_write_fd_n " to \"%s\" was incomplete: %z of %uz",
                      name, n, len);

        log->error_log_time = now;
    }
}


static ssize_t
ngx_http_upstream_log_script_write(ngx_http_request_t *r, ngx_http_log_script_t *script,
    u_char **name, u_char *buf, size_t len)
{
    size_t                              root;
    ssize_t                             n;
    ngx_str_t                           log, path;
    ngx_open_file_info_t                of;
    ngx_http_log_loc_conf_t            *llcf;
    ngx_http_core_loc_conf_t           *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (!r->root_tested) {

        /* test root directory existence */

        if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
            /* simulate successful logging */
            return len;
        }

        path.data[root] = '\0';

        ngx_memzero(&of, sizeof(ngx_open_file_info_t));

        of.valid = clcf->open_file_cache_valid;
        of.min_uses = clcf->open_file_cache_min_uses;
        of.test_dir = 1;
        of.test_only = 1;
        of.errors = clcf->open_file_cache_errors;
        of.events = clcf->open_file_cache_events;

        if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NGX_OK) {
            /* simulate successful logging */
            return len;
        }

        if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
            != NGX_OK)
        {
            if (of.err == 0) {
                /* simulate successful logging */
                return len;
            }

            ngx_log_error(NGX_LOG_ERR, r->connection->log, of.err,
                          "testing \"%s\" existence failed", path.data);

            /* simulate successful logging */
            return len;
        }

        if (!of.is_dir) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, NGX_ENOTDIR,
                          "testing \"%s\" existence failed", path.data);

            /* simulate successful logging */
            return len;
        }
    }

    if (ngx_http_script_run(r, &log, script->lengths->elts, 1,
                            script->values->elts)
        == NULL)
    {
        /* simulate successful logging */
        return len;
    }

    log.data[log.len - 1] = '\0';
    *name = log.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream log \"%s\"", log.data);

    llcf = ngx_http_get_module_loc_conf(r, ngx_http_log_module);

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.log = 1;
    of.valid = llcf->open_file_cache_valid;
    of.min_uses = llcf->open_file_cache_min_uses;
    of.directio = NGX_OPEN_FILE_DIRECTIO_OFF;

    if (ngx_http_set_disable_symlinks(r, clcf, &log, &of) != NGX_OK) {
        /* simulate successful logging */
        return len;
    }

    if (ngx_open_cached_file(llcf->open_file_cache, &log, &of, r->pool)
        != NGX_OK)
    {
        if (of.err == 0) {
            /* simulate successful logging */
            return len;
        }

        ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                      "%s \"%s\" failed", of.failed, log.data);
        /* simulate successful logging */
        return len;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream log #%d", of.fd);

    n = ngx_write_fd(of.fd, buf, len);

    return n;
}


#if (NGX_ZLIB)

static ssize_t
ngx_http_upstream_log_gzip(ngx_fd_t fd, u_char *buf, size_t len, ngx_int_t level,
    ngx_log_t *log)
{
    int          rc, wbits, memlevel;
    u_char      *out;
    size_t       size;
    ssize_t      n;
    z_stream     zstream;
    ngx_err_t    err;
    ngx_pool_t  *pool;

    wbits = MAX_WBITS;
    memlevel = MAX_MEM_LEVEL - 1;

    while ((ssize_t) len < ((1 << (wbits - 1)) - 262)) {
        wbits--;
        memlevel--;
    }

    /*
     * This is a formula from deflateBound() for conservative upper bound of
     * compressed data plus 18 bytes of gzip wrapper.
     */

    size = len + ((len + 7) >> 3) + ((len + 63) >> 6) + 5 + 18;

    ngx_memzero(&zstream, sizeof(z_stream));

    pool = ngx_create_pool(256, log);
    if (pool == NULL) {
        /* simulate successful logging */
        return len;
    }

    pool->log = log;

    zstream.zalloc = ngx_http_upstream_log_gzip_alloc;
    zstream.zfree = ngx_http_upstream_log_gzip_free;
    zstream.opaque = pool;

    out = ngx_pnalloc(pool, size);
    if (out == NULL) {
        goto done;
    }

    zstream.next_in = buf;
    zstream.avail_in = len;
    zstream.next_out = out;
    zstream.avail_out = size;

    rc = deflateInit2(&zstream, (int) level, Z_DEFLATED, wbits + 16, memlevel,
                      Z_DEFAULT_STRATEGY);

    if (rc != Z_OK) {
        ngx_log_error(NGX_LOG_ALERT, log, 0, "deflateInit2() failed: %d", rc);
        goto done;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, log, 0,
                   "deflate in: ni:%p no:%p ai:%ud ao:%ud",
                   zstream.next_in, zstream.next_out,
                   zstream.avail_in, zstream.avail_out);

    rc = deflate(&zstream, Z_FINISH);

    if (rc != Z_STREAM_END) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                      "deflate(Z_FINISH) failed: %d", rc);
        goto done;
    }

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, log, 0,
                   "deflate out: ni:%p no:%p ai:%ud ao:%ud rc:%d",
                   zstream.next_in, zstream.next_out,
                   zstream.avail_in, zstream.avail_out,
                   rc);

    size -= zstream.avail_out;

    rc = deflateEnd(&zstream);

    if (rc != Z_OK) {
        ngx_log_error(NGX_LOG_ALERT, log, 0, "deflateEnd() failed: %d", rc);
        goto done;
    }

    n = ngx_write_fd(fd, out, size);

    if (n != (ssize_t) size) {
        err = (n == -1) ? ngx_errno : 0;

        ngx_destroy_pool(pool);

        ngx_set_errno(err);
        return -1;
    }

done:

    ngx_destroy_pool(pool);

    /* simulate successful logging */
    return len;
}


static void *
ngx_http_upstream_log_gzip_alloc(void *opaque, u_int items, u_int size)
{
    ngx_pool_t *pool = opaque;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pool->log, 0,
                   "gzip alloc: n:%ud s:%ud", items, size);

    return ngx_palloc(pool, items * size);
}


static void
ngx_http_upstream_log_gzip_free(void *opaque, void *address)
{
#if 0
    ngx_pool_t *pool = opaque;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pool->log, 0, "gzip free: %p", address);
#endif
}

#endif


static void
ngx_http_upstream_log_flush(ngx_open_file_t *file, ngx_log_t *log)
{
    size_t                        len;
    ssize_t                       n;
    ngx_http_log_buf_t           *buffer;

    buffer = file->data;

    len = buffer->pos - buffer->start;

    if (len == 0) {
        return;
    }

#if (NGX_ZLIB)
    if (buffer->gzip) {
        n = ngx_http_upstream_log_gzip(file->fd, buffer->start, len, buffer->gzip, log);
    } else {
        n = ngx_write_fd(file->fd, buffer->start, len);
    }
#else
    n = ngx_write_fd(file->fd, buffer->start, len);
#endif

    if (n == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      ngx_write_fd_n " to \"%s\" failed",
                      file->name.data);

    } else if ((size_t) n != len) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                      ngx_write_fd_n " to \"%s\" was incomplete: %z of %uz",
                      file->name.data, n, len);
    }

    buffer->pos = buffer->start;

    if (buffer->event && buffer->event->timer_set) {
        ngx_del_timer(buffer->event);
    }
}


static void
ngx_http_upstream_log_flush_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "http upstream log buffer flush handler");

    ngx_http_upstream_log_flush(ev->data, ev->log);
}


static ngx_int_t
ngx_http_upstream_log_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_upstream_log_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_log_method_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_upstream_t *u;

    u = r->upstream;

    if (u && u->method_name.len > 0) {
        v->len = u->method_name.len;
        v->data = u->method_name.data;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
    } else {
        v->not_found = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_log_scheme_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_upstream_t *u;
    ngx_str_t scheme;

    u = r->upstream;

    if (u && u->schema.len > 0) {
        scheme.data = u->schema.data;
        scheme.len = u->schema.len;

        if (scheme.len > 3 && ngx_strncmp(&scheme.data[scheme.len - 3], "://", 3) == 0) {
            scheme.len -= 3;
        }

        v->len = scheme.len;
        v->data = scheme.data;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
    } else {
        v->not_found = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_log_uri_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_upstream_t     *u;
    ngx_str_t                uri;

    u = r->upstream;

    if (u && u->uri.len > 0) {
        uri.len = u->uri.len;
        uri.data = ngx_pnalloc(r->pool, uri.len);
        if (uri.data == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(uri.data, u->uri.data, uri.len);

        v->len = uri.len;
        v->data = uri.data;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
    } else {
        v->not_found = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_log_addr_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_upstream_state_t  *state;

    if (r->upstream && r->upstream->state && r->upstream->state->peer) {
        v->len = r->upstream->state->peer->len;
        v->data = ngx_pnalloc(r->pool, v->len);
        if (v->data == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(v->data, r->upstream->state->peer->data, v->len);
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        return NGX_OK;
    }

    if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    state = r->upstream_states->elts;
    state = &state[r->upstream_states->nelts - 1];
    
    if (state->peer) {
        v->len = state->peer->len;
        v->data = ngx_pnalloc(r->pool, v->len);
        if (v->data == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(v->data, state->peer->data, v->len);

    } else {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_log_status_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_upstream_state_t  *state;

    if (r->upstream && r->upstream->state && r->upstream->state->status) {
        state = r->upstream->state;

    } else {
        if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
            v->not_found = 1;
            return NGX_OK;
        }
        state = r->upstream_states->elts;
        state = &state[r->upstream_states->nelts - 1];
    }

    if (!state->status) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(v->data, "%ui", state->status) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_log_multi_ts_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    ngx_time_t                 *tp;
    size_t                      len;
    ngx_uint_t                  i;
    ngx_msec_t                  ms;
    ngx_http_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    len = r->upstream_states->nelts * (NGX_TIME_T_LEN + 4 + 2);

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->data = p;

    i = 0;
    state = r->upstream_states->elts;

    tp = ngx_timeofday();

    for ( ;; ) {

        switch (data) {

        case NGX_HTTP_UPSTREAM_LOG_START_TS:
            ms = state[i].start_msec;
            break;

#if (NGX_HTTP_SSL)
        case NGX_HTTP_UPSTREAM_LOG_SSL_START_TS:
            ms = state[i].ssl_start_msec;
            break;
#endif

        case NGX_HTTP_UPSTREAM_LOG_SEND_START_TS:
            ms = state[i].send_start_msec;
            break;

        case NGX_HTTP_UPSTREAM_LOG_SEND_END_TS:
            ms = state[i].send_end_msec;
            break;

        case NGX_HTTP_UPSTREAM_LOG_HEADER_TS:
            if (state[i].header_time == (ngx_msec_t) -1) {
                ms = (ngx_msec_t) -1;
            } else {
                ms = (ngx_msec_t) (state[i].start_msec + state[i].header_time);
            }
            break;

        case NGX_HTTP_UPSTREAM_LOG_END_TS:
            ms = (ngx_msec_t) (state[i].start_msec + state[i].response_time);
            break;

        default:
            v->not_found = 1;
            return NGX_OK;
        }

        if (ms != (ngx_msec_t) -1) {
            ms = (ngx_msec_t)
                (tp->sec * 1000 + tp->msec + ms - ngx_current_msec);
            p = ngx_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000);

        } else {
            *p++ = '-';
        }

        if (++i == r->upstream_states->nelts) {
            break;
        }

        if (state[i].peer) {
            *p++ = ',';
            *p++ = ' ';

        } else {
            *p++ = ' ';
            *p++ = ':';
            *p++ = ' ';

            if (++i == r->upstream_states->nelts) {
                break;
            }

            continue;
        }
    }

    v->len = p - v->data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_log_single_ts_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    ngx_time_t                 *tp;
    ngx_msec_t                  ms;
    ngx_http_upstream_state_t  *state;

    if (r->upstream && r->upstream->state) {
        state = r->upstream->state;

    } else {
        if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
            v->not_found = 1;
            return NGX_OK;
        }
        state = r->upstream_states->elts;
        state = &state[r->upstream_states->nelts - 1];
    }

    tp = ngx_timeofday();

    switch (data) {

    case NGX_HTTP_UPSTREAM_LOG_START_TS:
        ms = state->start_msec;
        break;

#if (NGX_HTTP_SSL)
    case NGX_HTTP_UPSTREAM_LOG_SSL_START_TS:
        ms = state->ssl_start_msec;
        break;
#endif

    case NGX_HTTP_UPSTREAM_LOG_SEND_START_TS:
        ms = state->send_start_msec;
        break;

    case NGX_HTTP_UPSTREAM_LOG_SEND_END_TS:
        ms = state->send_end_msec;
        break;

    case NGX_HTTP_UPSTREAM_LOG_HEADER_TS:
        if (state->header_time == (ngx_msec_t) -1) {
            ms = (ngx_msec_t) -1;
        } else {
            ms = (ngx_msec_t) (state->start_msec + state->header_time);
        }
        break;

    case NGX_HTTP_UPSTREAM_LOG_END_TS:
        ms = (ngx_msec_t) (state->start_msec + state->response_time);
        break;

    default:
        v->not_found = 1;
        return NGX_OK;
    }

    if (ms != (ngx_msec_t) -1) {
        ms = (ngx_msec_t)(tp->sec * 1000 + tp->msec + ms - ngx_current_msec);

        p = ngx_pnalloc(r->pool, NGX_TIME_T_LEN + 4);
        if (p == NULL) {
            return NGX_ERROR;
        }

        v->data = p;
        p = ngx_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000);
        v->len = p - v->data;

    } else {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_log_multi_time_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    size_t                      len;
    ngx_uint_t                  i;
    ngx_msec_int_t              ms;
    ngx_http_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    len = r->upstream_states->nelts * (NGX_TIME_T_LEN + 4 + 2);

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->data = p;

    i = 0;
    state = r->upstream_states->elts;

    for ( ;; ) {

        switch (data) {

        /* NGX_HTTP_UPSTREAM_LOG_CONNECT_TIME */

#if (NGX_HTTP_SSL)
        case NGX_HTTP_UPSTREAM_LOG_TRANSPORT_CONNECT_TIME:
            if (state[i].ssl_start_msec == (ngx_msec_t) -1) {
                ms = state[i].connect_time;
            } else {
                ms = (ngx_msec_t) (state[i].ssl_start_msec - state[i].start_msec);
            }
            break;

        case NGX_HTTP_UPSTREAM_LOG_SSL_TIME:
            if (state[i].ssl_start_msec == (ngx_msec_t) -1) {
                ms = (ngx_msec_t) -1;
            } else if (state[i].send_start_msec == (ngx_msec_t) -1) {
                ms = (ngx_msec_t) (state[i].start_msec + state[i].response_time - state[i].ssl_start_msec);
            } else {
                ms = (ngx_msec_t) (state[i].send_start_msec - state[i].ssl_start_msec);
            }
            break;
#else
        case NGX_HTTP_UPSTREAM_LOG_TRANSPORT_CONNECT_TIME:
            ms = state[i].connect_time;
            break;
#endif

        case NGX_HTTP_UPSTREAM_LOG_SEND_TIME:
            if (state[i].send_start_msec == (ngx_msec_t) -1) {
                ms = (ngx_msec_t) -1;
            } else if (state[i].send_end_msec == (ngx_msec_t) -1) {
                ms = (ngx_msec_t) (state[i].start_msec + state[i].response_time - state[i].send_start_msec);
            } else {
                ms = (ngx_msec_t) (state[i].send_end_msec - state[i].send_start_msec);
            }
            break;

        case NGX_HTTP_UPSTREAM_LOG_READ_TIME:
            if (state[i].send_end_msec == (ngx_msec_t) -1) {
                ms = (ngx_msec_t) -1;
            } else {
                ms = (ngx_msec_t) (state[i].start_msec + state[i].response_time - state[i].send_end_msec);
            }
            break;

        /* NGX_HTTP_UPSTREAM_LOG_HEADER_TIME */

        /* NGX_HTTP_UPSTREAM_LOG_RESPONSE_TIME */

        default:
            v->not_found = 1;
            return NGX_OK;
        }

        if (ms != -1) {
            ms = ngx_max(ms, 0);
            p = ngx_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000);

        } else {
            *p++ = '-';
        }

        if (++i == r->upstream_states->nelts) {
            break;
        }

        if (state[i].peer) {
            *p++ = ',';
            *p++ = ' ';

        } else {
            *p++ = ' ';
            *p++ = ':';
            *p++ = ' ';

            if (++i == r->upstream_states->nelts) {
                break;
            }

            continue;
        }
    }

    v->len = p - v->data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_log_single_time_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    ngx_msec_int_t              ms;
    ngx_http_upstream_state_t  *state;

    if (r->upstream && r->upstream->state) {
        state = r->upstream->state;

    } else {
        if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
            v->not_found = 1;
            return NGX_OK;
        }
        state = r->upstream_states->elts;
        state = &state[r->upstream_states->nelts - 1];
    }

    switch (data) {

    case NGX_HTTP_UPSTREAM_LOG_CONNECT_TIME:
        ms = state->connect_time;
        break;

#if (NGX_HTTP_SSL)
    case NGX_HTTP_UPSTREAM_LOG_TRANSPORT_CONNECT_TIME:
        if (state->ssl_start_msec == (ngx_msec_t) -1) {
            ms = state->connect_time;
        } else {
            ms = (ngx_msec_t) (state->ssl_start_msec - state->start_msec);
        }
        break;

    case NGX_HTTP_UPSTREAM_LOG_SSL_TIME:
        if (state->ssl_start_msec == (ngx_msec_t) -1) {
            ms = (ngx_msec_t) -1;
        } else if (state->send_start_msec == (ngx_msec_t) -1) {
            ms = (ngx_msec_t) (state->start_msec + state->response_time - state->ssl_start_msec);
        } else {
            ms = (ngx_msec_t) (state->send_start_msec - state->ssl_start_msec);
        }
        break;
#else
    case NGX_HTTP_UPSTREAM_LOG_TRANSPORT_CONNECT_TIME:
        ms = state->connect_time;
        break;
#endif

    case NGX_HTTP_UPSTREAM_LOG_SEND_TIME:
        if (state->send_start_msec == (ngx_msec_t) -1) {
            ms = (ngx_msec_t) -1;
        } else if (state->send_end_msec == (ngx_msec_t) -1) {
            ms = (ngx_msec_t) (state->start_msec + state->response_time - state->send_start_msec);
        } else {
            ms = (ngx_msec_t) (state->send_end_msec - state->send_start_msec);
        }
        break;

    case NGX_HTTP_UPSTREAM_LOG_READ_TIME:
        if (state->send_end_msec == (ngx_msec_t) -1) {
            ms = (ngx_msec_t) -1;
        } else {
            ms = (ngx_msec_t) (state->start_msec + state->response_time - state->send_end_msec);
        }
        break;

    case NGX_HTTP_UPSTREAM_LOG_HEADER_TIME:
        ms = state->header_time;
        break;
        
    case NGX_HTTP_UPSTREAM_LOG_RESPONSE_TIME:
        ms = state->response_time;
        break;

    default:
        v->not_found = 1;
        return NGX_OK;
    }

    if (ms != -1) {
        ms = ngx_max(ms, 0);

        p = ngx_pnalloc(r->pool, NGX_TIME_T_LEN + 4);
        if (p == NULL) {
            return NGX_ERROR;
        }

        v->data = p;
        p = ngx_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000);
        v->len = p - v->data;

    } else {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


#if 0
static ngx_int_t
ngx_http_upstream_log_multi_length_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    size_t                      len;
    ngx_uint_t                  i;
    ngx_http_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    len = r->upstream_states->nelts * (NGX_TIME_T_LEN + 4 + 2);

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->data = p;

    i = 0;
    state = r->upstream_states->elts;

    for ( ;; ) {

        switch(data) {

            /* NGX_HTTP_UPSTREAM_LOG_RESPONSE_LENGTH */

            /* NGX_HTTP_UPSTREAM_LOG_BYTES_RECEIVED */
            
            /* NGX_HTTP_UPSTREAM_LOG_BYTES_SENT */

            default:
                v->not_found = 1;
                return NGX_OK;
        }

        if (++i == r->upstream_states->nelts) {
            break;
        }

        if (state[i].peer) {
            *p++ = ',';
            *p++ = ' ';

        } else {
            *p++ = ' ';
            *p++ = ':';
            *p++ = ' ';

            if (++i == r->upstream_states->nelts) {
                break;
            }

            continue;
        }
    }

    v->len = p - v->data;

    return NGX_OK;
}
#endif

static ngx_int_t
ngx_http_upstream_log_single_length_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_upstream_state_t *state;
    u_char *p;

    if (r->upstream && r->upstream->state) {
        state = r->upstream->state;

    } else {
        if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
            v->not_found = 1;
            return NGX_OK;
        }
        state = r->upstream_states->elts;
        state = &state[r->upstream_states->nelts - 1];
    }

    p = ngx_pnalloc(r->pool, NGX_OFF_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->data = p;

    switch(data) {

    case NGX_HTTP_UPSTREAM_LOG_RESPONSE_LENGTH:
        p = ngx_sprintf(p, "%O", state->response_length);
        break;

    case NGX_HTTP_UPSTREAM_LOG_BYTES_RECEIVED:
        p = ngx_sprintf(p, "%O", state->bytes_received);
        break;
    
    case NGX_HTTP_UPSTREAM_LOG_BYTES_SENT:
        p = ngx_sprintf(p, "%O", state->bytes_sent);
        break;

    default:
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = p - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static void *
ngx_http_upstream_log_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_log_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_log_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
ngx_http_upstream_log_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_upstream_log_loc_conf_t *prev = parent;
    ngx_http_upstream_log_loc_conf_t *conf = child;

    if (conf->logs || conf->off) {
        return NGX_CONF_OK;
    }

    conf->logs = prev->logs;
    conf->off = prev->off;

    return NGX_CONF_OK;
}


static char *
ngx_http_upstream_log_set_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_log_loc_conf_t *ulcf = conf;

    ssize_t                                     size;
    ngx_int_t                                   gzip;
    ngx_uint_t                                  i, n;
    ngx_msec_t                                  flush;
    ngx_str_t                                  *value, name, s;
    ngx_http_log_t                             *log;
    ngx_syslog_peer_t                          *peer;
    ngx_http_log_buf_t                         *buffer;
    ngx_http_log_fmt_t                         *fmt;
    ngx_http_log_main_conf_t                   *lmcf;
    ngx_http_script_compile_t                   sc;
    ngx_http_compile_complex_value_t            ccv;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        ulcf->off = 1;
        if (cf->args->nelts == 2) {
            return NGX_CONF_OK;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    if (ulcf->logs == NULL) {
        ulcf->logs = ngx_array_create(cf->pool, 2, sizeof(ngx_http_log_t));
        if (ulcf->logs == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    lmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_log_module);

    log = ngx_array_push(ulcf->logs);
    if (log == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(log, sizeof(ngx_http_log_t));


    if (ngx_strncmp(value[1].data, "syslog:", 7) == 0) {

        peer = ngx_pcalloc(cf->pool, sizeof(ngx_syslog_peer_t));
        if (peer == NULL) {
            return NGX_CONF_ERROR;
        }

        if (ngx_syslog_process_conf(cf, peer) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }

        log->syslog_peer = peer;

        goto process_formats;
    }

    n = ngx_http_script_variables_count(&value[1]);

    if (n == 0) {
        log->file = ngx_conf_open_file(cf->cycle, &value[1]);
        if (log->file == NULL) {
            return NGX_CONF_ERROR;
        }

    } else {
        if (ngx_conf_full_name(cf->cycle, &value[1], 0) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        log->script = ngx_pcalloc(cf->pool, sizeof(ngx_http_log_script_t));
        if (log->script == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &value[1];
        sc.lengths = &log->script->lengths;
        sc.values = &log->script->values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

process_formats:

    if (cf->args->nelts >= 3) {
        name = value[2];

        if (ngx_strcmp(name.data, "combined") == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "upstream log can't use format \"%V\"", &name);
        }

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "upstream log format is required but not set");
    }

    fmt = lmcf->formats.elts;
    for (i = 0; i < lmcf->formats.nelts; i++) {
        if (fmt[i].name.len == name.len
            && ngx_strcasecmp(fmt[i].name.data, name.data) == 0)
        {
            log->format = &fmt[i];
            break;
        }
    }

    if (log->format == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unknown log format \"%V\"", &name);
        return NGX_CONF_ERROR;
    }

    size = 0;
    flush = 0;
    gzip = 0;

    for (i = 3; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "buffer=", 7) == 0) {
            s.len = value[i].len - 7;
            s.data = value[i].data + 7;

            size = ngx_parse_size(&s);

            if (size == NGX_ERROR || size == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid buffer size \"%V\"", &s);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "flush=", 6) == 0) {
            s.len = value[i].len - 6;
            s.data = value[i].data + 6;

            flush = ngx_parse_time(&s, 0);

            if (flush == (ngx_msec_t) NGX_ERROR || flush == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid flush time \"%V\"", &s);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "gzip", 4) == 0
            && (value[i].len == 4 || value[i].data[4] == '='))
        {
#if (NGX_ZLIB)
            if (size == 0) {
                size = 64 * 1024;
            }

            if (value[i].len == 4) {
                gzip = Z_BEST_SPEED;
                continue;
            }

            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            gzip = ngx_atoi(s.data, s.len);

            if (gzip < 1 || gzip > 9) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid compression level \"%V\"", &s);
                return NGX_CONF_ERROR;
            }

            continue;

#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "nginx was built without zlib support");
            return NGX_CONF_ERROR;
#endif
        }

        if (ngx_strncmp(value[i].data, "if=", 3) == 0) {
            s.len = value[i].len - 3;
            s.data = value[i].data + 3;

            ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &s;
            ccv.complex_value = ngx_palloc(cf->pool,
                                           sizeof(ngx_http_complex_value_t));
            if (ccv.complex_value == NULL) {
                return NGX_CONF_ERROR;
            }

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            log->filter = ccv.complex_value;

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (flush && size == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "no buffer is defined for access_log \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    if (size) {

        if (log->script) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "buffered logs cannot have variables in name");
            return NGX_CONF_ERROR;
        }

        if (log->syslog_peer) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "logs to syslog cannot be buffered");
            return NGX_CONF_ERROR;
        }

        if (log->file->data) {
            buffer = log->file->data;

            if (buffer->last - buffer->start != size
                || buffer->flush != flush
                || buffer->gzip != gzip)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "access_log \"%V\" already defined "
                                   "with conflicting parameters",
                                   &value[1]);
                return NGX_CONF_ERROR;
            }

            return NGX_CONF_OK;
        }

        buffer = ngx_pcalloc(cf->pool, sizeof(ngx_http_log_buf_t));
        if (buffer == NULL) {
            return NGX_CONF_ERROR;
        }

        buffer->start = ngx_pnalloc(cf->pool, size);
        if (buffer->start == NULL) {
            return NGX_CONF_ERROR;
        }

        buffer->pos = buffer->start;
        buffer->last = buffer->start + size;

        if (flush) {
            buffer->event = ngx_pcalloc(cf->pool, sizeof(ngx_event_t));
            if (buffer->event == NULL) {
                return NGX_CONF_ERROR;
            }

            buffer->event->data = log->file;
            buffer->event->handler = ngx_http_upstream_log_flush_handler;
            buffer->event->log = &cf->cycle->new_log;
            buffer->event->cancelable = 1;

            buffer->flush = flush;
        }

        buffer->gzip = gzip;

        log->file->flush = ngx_http_upstream_log_flush;
        log->file->data = buffer;
    }

    return NGX_CONF_OK;
}

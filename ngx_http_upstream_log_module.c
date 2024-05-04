
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Hanada
 */


#include "ngx_http_upstream_log_module.h"

#if (NGX_ZLIB)
#include <zlib.h>
#endif

typedef struct ngx_http_upstream_log_op_s  ngx_http_upstream_log_op_t;

typedef u_char *(*ngx_http_upstream_log_op_run_pt) (ngx_http_request_t *r, u_char *buf,
    ngx_http_upstream_log_op_t *op);

typedef size_t (*ngx_http_upstream_log_op_getlen_pt) (ngx_http_request_t *r,
    uintptr_t data);


struct ngx_http_upstream_log_op_s {
    size_t                               len;
    ngx_http_upstream_log_op_getlen_pt   getlen;
    ngx_http_upstream_log_op_run_pt      run;
    uintptr_t                            data;
};


typedef struct {
    ngx_str_t                            name;
    ngx_array_t                         *flushes;
    ngx_array_t                         *ops;        /* array of ngx_http_upstream_log_op_t */
} ngx_http_upstream_log_fmt_t;


typedef struct {
    ngx_array_t                          formats;    /* array of ngx_http_upstream_log_fmt_t */
    ngx_uint_t                           combined_used; /* unsigned  combined_used:1 */
} ngx_http_upstream_log_main_conf_t;


typedef struct {
    u_char                              *start;
    u_char                              *pos;
    u_char                              *last;

    ngx_event_t                         *event;
    ngx_msec_t                           flush;
    ngx_int_t                            gzip;
} ngx_http_upstream_log_buf_t;


typedef struct {
    ngx_array_t                         *lengths;
    ngx_array_t                         *values;
} ngx_http_upstream_log_script_t;


typedef struct {
    ngx_open_file_t                     *file;
    ngx_http_upstream_log_script_t      *script;
    time_t                               disk_full_time;
    time_t                               error_log_time;
    ngx_syslog_peer_t                   *syslog_peer;
    ngx_http_upstream_log_fmt_t         *format;
    ngx_http_complex_value_t            *filter;
} ngx_http_upstream_log_t;


typedef struct {
    ngx_array_t                         *logs;       /* array of ngx_http_upstream_log_t */

    ngx_open_file_cache_t               *open_file_cache;
    time_t                               open_file_cache_valid;
    ngx_uint_t                           open_file_cache_min_uses;

    ngx_flag_t                           escape_non_ascii;

    ngx_uint_t                           off;        /* unsigned  off:1 */
} ngx_http_upstream_log_loc_conf_t;


typedef struct {
    ngx_str_t                            name;
    size_t                               len;
    ngx_http_upstream_log_op_run_pt      run;
} ngx_http_upstream_log_var_t;


#define NGX_HTTP_UPSTREAM_LOG_ESCAPE_DEFAULT  0
#define NGX_HTTP_UPSTREAM_LOG_ESCAPE_JSON     1
#define NGX_HTTP_UPSTREAM_LOG_ESCAPE_NONE     2

static void ngx_http_upstream_log_write(ngx_http_request_t *r, ngx_http_upstream_log_t *log,
    u_char *buf, size_t len);
static ssize_t ngx_http_upstream_log_script_write(ngx_http_request_t *r,
    ngx_http_upstream_log_script_t *script, u_char **name, u_char *buf, size_t len);

#if (NGX_ZLIB)
static ssize_t ngx_http_upstream_log_gzip(ngx_fd_t fd, u_char *buf, size_t len,
    ngx_int_t level, ngx_log_t *log);

static void *ngx_http_upstream_log_gzip_alloc(void *opaque, u_int items, u_int size);
static void ngx_http_upstream_log_gzip_free(void *opaque, void *address);
#endif

static void ngx_http_upstream_log_flush(ngx_open_file_t *file, ngx_log_t *log);
static void ngx_http_upstream_log_flush_handler(ngx_event_t *ev);

static u_char *ngx_http_upstream_log_pipe(ngx_http_request_t *r, u_char *buf,
    ngx_http_upstream_log_op_t *op);
static u_char *ngx_http_upstream_log_time(ngx_http_request_t *r, u_char *buf,
    ngx_http_upstream_log_op_t *op);
static u_char *ngx_http_upstream_log_iso8601(ngx_http_request_t *r, u_char *buf,
    ngx_http_upstream_log_op_t *op);
static u_char *ngx_http_upstream_log_msec(ngx_http_request_t *r, u_char *buf,
    ngx_http_upstream_log_op_t *op);
static u_char *ngx_http_upstream_log_request_time(ngx_http_request_t *r, u_char *buf,
    ngx_http_upstream_log_op_t *op);
static u_char *ngx_http_upstream_log_status(ngx_http_request_t *r, u_char *buf,
    ngx_http_upstream_log_op_t *op);
static u_char *ngx_http_upstream_log_bytes_sent(ngx_http_request_t *r, u_char *buf,
    ngx_http_upstream_log_op_t *op);
static u_char *ngx_http_upstream_log_body_bytes_sent(ngx_http_request_t *r,
    u_char *buf, ngx_http_upstream_log_op_t *op);
static u_char *ngx_http_upstream_log_request_length(ngx_http_request_t *r, u_char *buf,
    ngx_http_upstream_log_op_t *op);

static ngx_int_t ngx_http_upstream_log_variable_compile(ngx_conf_t *cf,
    ngx_http_upstream_log_op_t *op, ngx_str_t *value, ngx_uint_t escape);
static size_t ngx_http_upstream_log_variable_getlen(ngx_http_request_t *r,
    uintptr_t data);
static u_char *ngx_http_upstream_log_variable(ngx_http_request_t *r, u_char *buf,
    ngx_http_upstream_log_op_t *op);
static uintptr_t ngx_http_upstream_log_escape(ngx_http_upstream_log_loc_conf_t *lcf, u_char *dst,
    u_char *src, size_t size);
static size_t ngx_http_upstream_log_json_variable_getlen(ngx_http_request_t *r,
    uintptr_t data);
static u_char *ngx_http_upstream_log_json_variable(ngx_http_request_t *r, u_char *buf,
    ngx_http_upstream_log_op_t *op);
static size_t ngx_http_upstream_log_unescaped_variable_getlen(ngx_http_request_t *r,
    uintptr_t data);
static u_char *ngx_http_upstream_log_unescaped_variable(ngx_http_request_t *r,
    u_char *buf, ngx_http_upstream_log_op_t *op);


static void *ngx_http_upstream_log_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_upstream_log_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_log_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_upstream_log_set_log(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_upstream_log_set_format(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_upstream_log_compile_format(ngx_conf_t *cf,
    ngx_array_t *flushes, ngx_array_t *ops, ngx_array_t *args, ngx_uint_t s);
static char *ngx_http_upstream_log_open_file_cache(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_upstream_log_init(ngx_conf_t *cf);


static ngx_command_t ngx_http_upstream_log_commands[] = {

    { ngx_string("upstream_log_format"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
      ngx_http_upstream_log_set_format,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("upstream_log"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_HTTP_LMT_CONF|NGX_CONF_1MORE,
      ngx_http_upstream_log_set_log,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("upstream_open_log_file_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_http_upstream_log_open_file_cache,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("upstream_log_escape_non_ascii"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upstream_log_loc_conf_t, escape_non_ascii),
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_log_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_upstream_log_init,                     /* postconfiguration */

    ngx_http_upstream_log_create_main_conf,         /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_upstream_log_create_loc_conf,          /* create location configuration */
    ngx_http_upstream_log_merge_loc_conf            /* merge location configuration */
};


ngx_module_t ngx_http_upstream_log_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_log_module_ctx,       /* module context */
    ngx_http_upstream_log_commands,          /* module directives */
    NGX_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    NULL,                                    /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t  ngx_http_upstream_log = ngx_string(NGX_HTTP_LOG_PATH);


static ngx_str_t  ngx_http_upstream_combined_fmt =
    ngx_string("$remote_addr - $remote_user [$time_local] "
               "\"$request\" $status $body_bytes_sent "
               "\"$http_referer\" \"$http_user_agent\"");


static ngx_http_upstream_log_var_t  ngx_http_upstream_log_vars[] = {
    { ngx_string("pipe"), 1, ngx_http_upstream_log_pipe },
    { ngx_string("time_local"), sizeof("28/Sep/1970:12:00:00 +0600") - 1,
                          ngx_http_upstream_log_time },
    { ngx_string("time_iso8601"), sizeof("1970-09-28T12:00:00+06:00") - 1,
                          ngx_http_upstream_log_iso8601 },
    { ngx_string("msec"), NGX_TIME_T_LEN + 4, ngx_http_upstream_log_msec },
    { ngx_string("request_time"), NGX_TIME_T_LEN + 4,
                          ngx_http_upstream_log_request_time },
    { ngx_string("status"), NGX_INT_T_LEN, ngx_http_upstream_log_status },
    { ngx_string("bytes_sent"), NGX_OFF_T_LEN, ngx_http_upstream_log_bytes_sent },
    { ngx_string("body_bytes_sent"), NGX_OFF_T_LEN,
                          ngx_http_upstream_log_body_bytes_sent },
    { ngx_string("request_length"), NGX_SIZE_T_LEN,
                          ngx_http_upstream_log_request_length },

    { ngx_null_string, 0, NULL }
};


static void *
ngx_http_upstream_log_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_upstream_log_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_log_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->logs = NGX_CONF_UNSET_PTR;

    return conf;
}

static char *
ngx_http_upstream_log_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_upstream_log_loc_conf_t *prev = parent;
    ngx_http_upstream_log_loc_conf_t *conf = child;

    if (conf->logs == NGX_CONF_UNSET_PTR) {
        conf->logs = (prev->logs == NGX_CONF_UNSET_PTR) ? NULL : prev->logs;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_upstream_log_set_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_upstream_log_loc_conf_t *ulcf = conf;

    if (ulcf->logs == NULL) {
        ulcf->logs = ngx_array_create(cf->pool, 1, sizeof(ngx_http_upstream_log_t *));
        if (ulcf->logs == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    ngx_http_upstream_log_t *log = ngx_array_push(ulcf->logs);
    if (log == NULL) {
        return NGX_CONF_ERROR;
    }

    return ngx_http_upstream_log_set_log(cf, cmd, log);
}

ngx_int_t ngx_http_upstream_log_handler(ngx_http_request_t *r, ngx_http_upstream_t *u) {
    // Add your custom logging logic here
    // This is just a placeholder for where you would integrate your logging logic
}

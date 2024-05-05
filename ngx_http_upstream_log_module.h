
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Hanada
 */


#ifndef _NGX_HTTP_UPSTREAM_LOG_MODULE_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_LOG_MODULE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

ngx_int_t ngx_http_upstream_log_handler(ngx_http_request_t *r);

#endif /* _NGX_HTTP_UPSTREAM_LOG_MODULE_H_INCLUDED_ */

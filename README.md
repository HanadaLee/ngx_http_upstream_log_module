# Name

ngx_http_upstream_log_module

The ngx_http_upstream_log_module module writes upstream request logs in the specified format, like ngx_http_log_module.
Most of the work of this module originates from ngx_http_log_module.

# Description

Unlike the access log module, it will be logged at the end of each upstream request. If several servers were contacted during request processing, an upstream log is recorded at the end of each contact. If an internal redirect from one server group to another happens, initiated by “X-Accel-Redirect” or error_page, an upstream log will also be recorded at the end of each contact.

This module also provides a series of variables for upstream logging. Many of these variables start with $upstream_last_, which is used to distinguish them from the variables in ngx_http_upstream. These variables only return information related to the current contact with the upstream, or information related to the last time the upstream was contacted. Commas and colons are not used to record information about multiple contacts with the upstream.

The usage of this module is very similar to ngx_http_log_module. just use the upstream_log directive to sets the path, format, and configuration for a buffered log write.

# Status

This Nginx module is currently considered experimental. Issues and PRs are welcome if you encounter any problems.

# Synopsis

```
    http {

        log_format access '$remote_addr - $remote_user [$time_local] "$request" '
                        '$status $body_bytes_sent "$http_referer" '
                        '"$http_user_agent" "$http_x_forwarded_for"';

        log_format upstream '$remote_addr $upstream_last_addr [$time_local] "$upstream_method $upstream_uri" '
                                 '$upstream_last_status $upstream_last_response_length $upstream_last_bytes_sent $upstream_last_bytes_received '
                                 '$upstream_last_connect_time $upstream_last_header_time $upstream_last_response_time';

        upstream cluster {
            server 192.168.0.1:80;
            server 192.168.0.2:80;
        }

        server {
            listen 80;

            access_log logs/access.log access;
            upstream_log logs/upstream.log upstream;

            location / {
                proxy_pass http://cluster;
            }
        }

    }
```

# Installation

In order to use this module, you must patch nginx firstly. Then configure your nginx branch with --add-module=/path/to/ngx_http_upstream_log_module

```
$ wget 'https://nginx.org/download/nginx-1.26.0.tar.gz'
$ tar -xzvf nginx-1.26.0.tar.gz
$ cd nginx-1.26.0
$ patch -p1 < /path/to/ngx_http_upstream_log_module/ngx_http_upstream_log_1.25.3+.patch

$ ./configure --add-module=/path/to/ngx_http_upstream_log_module

$ make
$ make install
```

# Directive

### upstream_log
* Syntax:	upstream_log path [format [buffer=size] [gzip[=level]] [flush=time] [if=condition]]; upstream_log off;
* Default:	-;
* Context:	http, server, location, if in location, limit_except

Sets the path, format, and configuration for a buffered log write. Several logs can be specified on the same configuration level. Logging to syslog can be configured by specifying the “syslog:” prefix in the first parameter. The special value off cancels all upstream_log directives on the current level. Unlike the access_log directive, this directive does not accept the predefined "combined" format. You must first define the log format using the log_format directive and then reference it using this directive.

If either the buffer or gzip parameter is used, writes to log will be buffered.

> The buffer size must not exceed the size of an atomic write to a disk file. For FreeBSD this size is unlimited.

When buffering is enabled, the data will be written to the file:

* if the next log line does not fit into the buffer;
* if the buffered data is older than specified by the flush parameter;
* when a worker process is re-opening log files or is shutting down.
If the gzip parameter is used, then the buffered data will be compressed before writing to the file. The compression level can be set between 1 (fastest, less compression) and 9 (slowest, best compression). By default, the buffer size is equal to 64K bytes, and the compression level is set to 1. Since the data is compressed in atomic blocks, the log file can be decompressed or read by “zcat” at any time.

Example:
```
upstream_log /path/to/log.gz upstream gzip flush=5m;
```
> For gzip compression to work, nginx must be built with the zlib library.
The file path can contain variables, but such logs have some constraints:

* the user whose credentials are used by worker processes should have permissions to create files in a directory with such logs;
* buffered writes do not work;
* the file is opened and closed for each log write. However, since the descriptors of frequently used files can be stored in a cache, writing to the old file can continue during the time specified by the open_log_file_cache directive’s valid parameter
* during each log write the existence of the request’s root directory is checked, and if it does not exist the log is not created. It is thus a good idea to specify both root and upstream_log on the same configuration level:
```
server {
    root         /spool/vhost/data/$host;
    upstream_log /spool/vhost/logs/$host;
    ...
```
The if parameter enables conditional logging. A request will not be logged if the condition evaluates to “0” or an empty string. In the following example, the last requests with response codes 2xx and 3xx will not be logged:
```
map $upstream_status $upstream_loggable {
    ~(?:^|:\s|,\s)[23][0-9]{2}  0;
    default 1;
}

upstream_log /path/to/upstream.log upstream if=$upstream_loggable;
```

# Authors

Hanada im@hanada.info

# License

This Nginx module is licensed under BSD 2-Clause License.
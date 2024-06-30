# Name

ngx_http_upstream_log_module

The ngx_http_upstream_log_module module writes upstream request logs in the specified format, like ngx_http_log_module.
Most of the work of this module originates from ngx_http_log_module.

# Description

Unlike the access log module, it will be logged at the end of each upstream request. If several servers were contacted during request processing, an upstream log is recorded at the end of each contact. If an internal redirect from one server group to another happens, initiated by “X-Accel-Redirect” or error_page, an upstream log will also be recorded at the end of each contact.

This module also provides a series of variables for upstream logging. Many of these variables start with $upstream_last_, which is used to distinguish them from the variables in ngx_http_upstream. These variables only return information related to the current contact with the upstream, or information related to the last time the upstream was contacted. Commas and colons are not used to record information about multiple contacts with the upstream.

The usage of this module is very similar to ngx_http_log_module. For example, use the upstream_log_format directive to specify the format of the upstream log. Use the upstream_log directive to sets the path, format, and configuration for a buffered log write.

# Status

This Nginx module is currently considered experimental. Issues and PRs are welcome if you encounter any problems.

# Synopsis

```
    http {

        log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                        '$status $body_bytes_sent "$http_referer" '
                        '"$http_user_agent" "$http_x_forwarded_for"';

        upstream_log_format main '$remote_addr $upstream_last_addr [$time_local] "$upstream_method $upstream_uri" '
                                 '$upstream_last_status $upstream_last_response_length $upstream_last_bytes_sent $upstream_last_bytes_received '
                                 '$upstream_last_connect_time $upstream_last_header_time $upstream_last_response_time';

        upstream cluster {
            server 192.168.0.1:80;
            server 192.168.0.2:80;
        }

        server {
            listen 80;

            access_log logs/access.log main;
            upstream_log logs/upstream.log main;

            location / {
                proxy_pass http://cluster;
            }
        }

    }
```

# Installation

In order to use this module, you must first patch nginx. Then configure your nginx branch with --add-module=/path/to/ngx_http_upstream_log_module

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
* Default:	upstream_log logs/upstream.log combined;
* Context:	http, server, location, if in location, limit_except

Sets the path, format, and configuration for a buffered log write. Several logs can be specified on the same configuration level. Logging to syslog can be configured by specifying the “syslog:” prefix in the first parameter. The special value off cancels all upstream_log directives on the current level. If the format is not specified then the predefined “combined” format is used.

If either the buffer or gzip parameter is used, writes to log will be buffered.

> The buffer size must not exceed the size of an atomic write to a disk file. For FreeBSD this size is unlimited.

When buffering is enabled, the data will be written to the file:

* if the next log line does not fit into the buffer;
* if the buffered data is older than specified by the flush parameter;
* when a worker process is re-opening log files or is shutting down.
If the gzip parameter is used, then the buffered data will be compressed before writing to the file. The compression level can be set between 1 (fastest, less compression) and 9 (slowest, best compression). By default, the buffer size is equal to 64K bytes, and the compression level is set to 1. Since the data is compressed in atomic blocks, the log file can be decompressed or read by “zcat” at any time.

Example:
```
upstream_log /path/to/log.gz combined gzip flush=5m;
```
> For gzip compression to work, nginx must be built with the zlib library.
The file path can contain variables, but such logs have some constraints:

* the user whose credentials are used by worker processes should have permissions to create files in a directory with such logs;
* buffered writes do not work;
* the file is opened and closed for each log write. However, since the descriptors of frequently used files can be stored in a cache, writing to the old file can continue during the time specified by the upstream_open_log_file_cache directive’s valid parameter
* during each log write the existence of the request’s root directory is checked, and if it does not exist the log is not created. It is thus a good idea to specify both root and upstream_log on the same configuration level:
```
server {
    root         /spool/vhost/data/$host;
    upstream_log /spool/vhost/logs/$host;
    ...
```
The if parameter enables conditional logging. A request will not be logged if the condition evaluates to “0” or an empty string. In the following example, the requests with response codes 2xx and 3xx will not be logged:
```
map $upstream_log_status $upstream_loggable {
    ~^[23]  0;
    default 1;
}

upstream_log /path/to/upstream.log combined if=$upstream_loggable;
```

### upstream_log_format

* Syntax:	upstream_log_format name [escape=default|json|none] string ...;
* Default:	upstream_log_format combined "...";
* Context:	http

Specifies log format.

Format names can duplicate those defined by log_format, but this is generally not recommended.

The escape parameter allows setting json or default characters escaping in variables, by default, default escaping is used. The none value disables escaping.

For default escaping, characters “"”, “\”, and other characters with values less than 32 or above 126 are escaped as “\xXX”. If the variable value is not found, a hyphen (“-”) will be logged.

For json escaping, all characters not allowed in JSON strings will be escaped: characters “"” and “\” are escaped as “\"” and “\\\”, characters with values less than 32 are escaped as “\n”, “\r”, “\t”, “\b”, “\f”, or “\u00XX”.

The configuration always includes the predefined “combined” format:
```
upstream_log_format combined '$remote_addr $upstream_log_addr [$time_local] "$upstream_method $upstream_uri" '
                             '$upstream_log_status $upstream_log_response_length $upstream_log_bytes_sent $upstream_log_bytes_received '
                             '$upstream_log_connect_time $upstream_log_header_time $upstream_log_response_time';
```

### upstream_open_log_file_cache
* Syntax:	upstream_open_log_file_cache max=N [inactive=time] [min_uses=N] [valid=time]; upstream_open_log_file_cache off;
* Default:	upstream_open_log_file_cache off;
* Context:	http, server, location


Defines a cache that stores the file descriptors of frequently used logs whose names contain variables. The directive has the following parameters:

* max
sets the maximum number of descriptors in a cache; if the cache becomes full the least recently used (LRU) descriptors are closed
* inactive
sets the time after which the cached descriptor is closed if there were no access during this time; by default, 10 seconds
* min_uses
sets the minimum number of file uses during the time defined by the inactive parameter to let the descriptor stay open in a cache; by default, 1
* valid
sets the time after which it should be checked that the file still exists with the same name; by default, 60 seconds
* off
disables caching

Usage example:
```
upstream_open_log_file_cache max=1000 inactive=20s valid=1m min_uses=2;
```


# Variable

### \$upstream_method
upstream method, usually “GET” or “POST”.

### \$upstream_scheme
upstream scheme, "http" or "https".

### \$upstream_uri
full upstream request uri.

### \$upstream_last_addr
keeps the IP address and port, or the path to the UNIX-domain socket of the latest upstream server.

### \$upstream_last_status
keeps status code of the response obtained from the latest upstream server.

### \$upstream_start_ts
keeps timestamp of upstream starts; the time is kept in seconds with millisecond resolution. Times of several responses are separated by commas and colons like addresses in the $upstream_addr variable.

### \$upstream_last_start_ts
keeps timestamp of latest upstream starts; the time is kept in seconds with millisecond resolution.

### \$upstream_ssl_start_ts
keeps timestamp of upstream ssl handshake starts; the time is kept in seconds with millisecond resolution. Times of several responses are separated by commas and colons like addresses in the $upstream_addr variable.

### \$upstream_last_ssl_start_ts
keeps timestamp of latest upstream ssl handshake starts; the time is kept in seconds with millisecond resolution.

### \$upstream_send_start_ts
keeps timestamp of upstream request send starts; the time is kept in seconds with millisecond resolution. Times of several responses are separated by commas and colons like addresses in the $upstream_addr variable.

### \$upstream_last_send_start_ts
keeps timestamp of latest upstream request send starts; the time is kept in seconds with millisecond resolution.

### \$upstream_send_end_ts
keeps timestamp of upstream request send ends; the time is kept in seconds with millisecond resolution. Times of several responses are separated by commas and colons like addresses in the $upstream_addr variable.

### \$upstream_last_send_end_ts
keeps timestamp of latest upstream request send ends; the time is kept in seconds with millisecond resolution.

### \$upstream_header_ts
keeps timestamp of upstream response header sent; the time is kept in seconds with millisecond resolution. Times of several responses are separated by commas and colons like addresses in the $upstream_addr variable.

### \$upstream_last_header_ts
keeps timestamp of latest upstream response header sent; the time is kept in seconds with millisecond resolution.

### \$upstream_end_ts
keeps timestamp of upstream response sent or abnormal interruption; the time is kept in seconds with millisecond resolution. Times of several responses are separated by commas and colons like addresses in the $upstream_addr variable.

### \$upstream_last_end_ts
keeps timestamp of latest upstream response sent or abnormal interruption; the time is kept in seconds with millisecond resolution.

### \$upstream_last_connect_time
keeps time spent on establishing a connection with the upstream server; the time is kept in seconds with millisecond resolution. In case of SSL, includes time spent on handshake.

### \$upstream_transport_connect_time
keeps time spent on establishing a connection with the upstream server; the time is kept in seconds with millisecond resolution. In case of SSL, does not include time spent on handshake. Times of several connections are separated by commas and colons like addresses in the $upstream_addr variable.

### \$upstream_last_transport_connect_time
keeps time spent on establishing a connection with the upstream server; the time is kept in seconds with millisecond resolution. In case of SSL, does not include time spent on handshake.

### \$upstream_ssl_time
keeps time spent on upstream ssl handshake; the time is kept in seconds with millisecond resolution. Note that this timing starts only after receiving the upstream request header. Times of several ssl connections are separated by commas and colons like addresses in the $upstream_addr variable.

### \$upstream_last_ssl_time
keeps time spent on latest upstream ssl handshake; the time is kept in seconds with millisecond resolution. Note that this timing starts only after receiving the upstream request header.

### \$upstream_send_time
keeps time spent on sending request to the upstream server; the time is kept in seconds with millisecond resolution. Times of several send requests are separated by commas and colons like addresses in the $upstream_addr variable.

### \$upstream_last_send_time
keeps time spent on sending request to the latest upstream server; the time is kept in seconds with millisecond resolution.

### \$upstream_read_time
keeps time spent on reading response from the upstream server; the time is kept in seconds with millisecond resolution. Note that this timing starts only after receiving the upstream request header. Times of several responses are separated by commas and colons like addresses in the $upstream_addr variable.

### \$upstream_last_read_time
keeps time spent on reading response from the latest upstream server; the time is kept in seconds with millisecond resolution. Note that this timing starts only after receiving the upstream request header.

### \$upstream_last_header_time
keeps time spent on receiving the response header from the latest upstream server; the time is kept in seconds with millisecond resolution.

### \$upstream_last_response_time
keeps time spent on receiving the response from the latest upstream server; the time is kept in seconds with millisecond resolution.

### \$upstream_last_response_length
keeps the length of the response obtained from the upstream server; the length is kept in bytes.

### \$upstream_last_bytes_received
number of bytes received from an upstream server.

### \$upstream_last_bytes_sent
number of bytes sent to an upstream server.

# Authors

Hanada im@hanada.info

# License

This Nginx module is licensed under BSD 2-Clause License.
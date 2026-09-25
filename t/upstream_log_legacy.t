#!/usr/bin/perl

# Tests for upstream_log without ngx_expr_module.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use Test::Nginx qw/ :DEFAULT /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy
	ngx_http_upstream_log_module/);

plan(skip_all => 'legacy upstream_log build required')
	if $t->has_module('ngx_expr_module');

$t->plan(8);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    log_format upstream_test '$uri|$arg_id|$upstream_status';

    server {
        listen       127.0.0.1:8081;
        server_name  backend;

        location / {
            return 200 backend;
        }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location = /filtered {
            upstream_log %%TESTDIR%%/filtered.log upstream_test if=$arg_log;
            proxy_pass http://127.0.0.1:8081;
        }

        location = /multiple {
            upstream_log %%TESTDIR%%/legacy-one.log upstream_test;
            upstream_log %%TESTDIR%%/legacy-two.log upstream_test;
            proxy_pass http://127.0.0.1:8081;
        }
    }

    server {
        listen       127.0.0.1:8082;
        server_name  inheritance;

        upstream_log %%TESTDIR%%/legacy-parent.log upstream_test;

        location = /inherit {
            proxy_pass http://127.0.0.1:8081;
        }

        location = /off {
            upstream_log off;
            proxy_pass http://127.0.0.1:8081;
        }

        location = /replace {
            upstream_log %%TESTDIR%%/legacy-child.log upstream_test;
            proxy_pass http://127.0.0.1:8081;
        }
    }
}

EOF

$t->run();

###############################################################################

response('/filtered?id=one&log=1', 8080);
response('/filtered?id=zero&log=0', 8080);
response('/filtered?id=empty&log=', 8080);
response('/filtered?id=text&log=yes', 8080);
is($t->read_file('filtered.log'),
	"/filtered|one|200\n/filtered|text|200\n",
	'legacy if parameter filters false values');

response('/multiple?id=multi', 8080);
is($t->read_file('legacy-one.log'), "/multiple|multi|200\n",
	'legacy first log is written');
is($t->read_file('legacy-two.log'), "/multiple|multi|200\n",
	'legacy second log is written');

response('/inherit?id=parent', 8082);
is($t->read_file('legacy-parent.log'), "/inherit|parent|200\n",
	'legacy parent log is inherited');

response('/off?id=off', 8082);
is($t->read_file('legacy-parent.log'), "/inherit|parent|200\n",
	'legacy off cancels inherited logs');

response('/replace?id=child', 8082);
is($t->read_file('legacy-child.log'), "/replace|child|200\n",
	'legacy local log is written');
is($t->read_file('legacy-parent.log'), "/inherit|parent|200\n",
	'legacy local entries replace inherited entries');

like(response('/filtered?id=status&log=1', 8080), qr/^HTTP\/1\.1 200 /,
	'legacy filtering preserves the upstream response');

###############################################################################

sub response {
	my ($uri, $port) = @_;

	return http("GET $uri HTTP/1.1\x0d\x0a"
		. "Host: localhost\x0d\x0a"
		. "Connection: close\x0d\x0a\x0d\x0a",
		PeerAddr => '127.0.0.1:' . port($port));
}

###############################################################################

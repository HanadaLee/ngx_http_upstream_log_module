#!/usr/bin/perl

# Tests for upstream_log with ngx_expr_module.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use Test::Nginx qw/ :DEFAULT /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy rewrite ngx_expr_module
	ngx_http_upstream_log_module/)->plan(31);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    log_format upstream_test '$uri|$arg_id|$upstream_status';

    upstream retry_backend {
        server 127.0.0.1:8999;
        server 127.0.0.1:8081 backup;
    }

    server {
        listen       127.0.0.1:8081;
        server_name  backend;

        location = /fail {
            return 503 failure;
        }

        location / {
            return 200 backend;
        }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        expr selected str_eq $arg_log yes;
        expr stop str_eq $arg_stop yes;
        expr upstream_error str_regex_match $upstream_status '^5';

        location = /basic {
            upstream_log %%TESTDIR%%/basic.log upstream_test;
            proxy_pass http://127.0.0.1:8081;
        }

        location = /multiple {
            upstream_log %%TESTDIR%%/multiple-one.log upstream_test;
            upstream_log %%TESTDIR%%/multiple-two.log upstream_test;
            proxy_pass http://127.0.0.1:8081;
        }

        location = /conditional {
            when selected {
                upstream_log %%TESTDIR%%/conditional.log upstream_test;
            }

            upstream_log %%TESTDIR%%/conditional-always.log upstream_test;
            proxy_pass http://127.0.0.1:8081;
        }

        location = /ordered-off {
            upstream_log %%TESTDIR%%/ordered-before.log upstream_test;

            when stop {
                upstream_log off;
            }

            upstream_log %%TESTDIR%%/ordered-after.log upstream_test;
            proxy_pass http://127.0.0.1:8081;
        }

        location = /if {
            upstream_log %%TESTDIR%%/if.log upstream_test if=$arg_gate;
            when selected {
                upstream_log %%TESTDIR%%/when-if.log upstream_test if=$arg_gate;
            }
            proxy_pass http://127.0.0.1:8081;
        }

        location = /unconditional-off {
            upstream_log %%TESTDIR%%/off-before.log upstream_test;
            upstream_log off;
            upstream_log %%TESTDIR%%/off-after.log upstream_test;
            proxy_pass http://127.0.0.1:8081;
        }

        location = /upstream-ok {
            when upstream_error {
                upstream_log %%TESTDIR%%/upstream-error.log upstream_test;
            }

            proxy_pass http://127.0.0.1:8081;
        }

        location = /upstream-fail {
            when upstream_error {
                upstream_log %%TESTDIR%%/upstream-error.log upstream_test;
            }

            proxy_pass http://127.0.0.1:8081/fail;
        }

        location = /variable-path {
            upstream_log %%TESTDIR%%/variable-$arg_name.log upstream_test;
            proxy_pass http://127.0.0.1:8081;
        }

        location = /retry {
            upstream_log %%TESTDIR%%/retry.log upstream_test;
            proxy_next_upstream error;
            proxy_next_upstream_tries 2;
            proxy_pass http://retry_backend;
        }
    }

    server {
        listen       127.0.0.1:8082;
        server_name  inheritance;

        upstream_log %%TESTDIR%%/inherited.log upstream_test;

        location = /inherit {
            proxy_pass http://127.0.0.1:8081;
        }

        location = /replace {
            upstream_log %%TESTDIR%%/child.log upstream_test;
            proxy_pass http://127.0.0.1:8081;
        }
    }
}

EOF

$t->run();

###############################################################################

like(response('/basic?id=one', 8080), qr/^HTTP\/1\.1 200 /,
	'basic upstream request succeeds');
is($t->read_file('basic.log'), "/basic|one|200\n",
	'basic upstream contact is logged');

response('/multiple?id=two', 8080);
is($t->read_file('multiple-one.log'), "/multiple|two|200\n",
	'first log at the same level is written');
is($t->read_file('multiple-two.log'), "/multiple|two|200\n",
	'second log at the same level is written');

response('/conditional?id=hit&log=yes', 8080);
response('/conditional?id=miss&log=no', 8080);
is($t->read_file('conditional.log'), "/conditional|hit|200\n",
	'conditional log records only matching requests');
is($t->read_file('conditional-always.log'),
	"/conditional|hit|200\n/conditional|miss|200\n",
	'unconditional log records both requests');

response('/ordered-off?id=stop&stop=yes', 8080);
response('/ordered-off?id=continue&stop=no', 8080);
is($t->read_file('ordered-before.log'),
	"/ordered-off|stop|200\n/ordered-off|continue|200\n",
	'entries before conditional off are retained');
is($t->read_file('ordered-after.log'), "/ordered-off|continue|200\n",
	'matching conditional off stops subsequent entries');

response('/unconditional-off?id=off', 8080);
is($t->read_file('off-before.log'), "/unconditional-off|off|200\n",
	'entry before unconditional off is retained');
is($t->read_file('off-after.log'), '',
	'unconditional off stops subsequent entries');

response('/upstream-ok?id=ok', 8080);
response('/upstream-fail?id=fail', 8080);
is($t->read_file('upstream-error.log'), "/upstream-fail|fail|503\n",
	'condition can inspect the completed upstream status');

response('/variable-path?id=var&name=selected', 8080);
is($t->read_file('variable-selected.log'), "/variable-path|var|200\n",
	'variables are evaluated in the log path');

response('/inherit?id=parent', 8082);
is($t->read_file('inherited.log'), "/inherit|parent|200\n",
	'parent log configuration is inherited');

response('/replace?id=child', 8082);
is($t->read_file('child.log'), "/replace|child|200\n",
	'local log configuration is used');
is($t->read_file('inherited.log'), "/inherit|parent|200\n",
	'local entries replace inherited entries');

like(response('/retry?id=retry', 8080), qr/^HTTP\/1\.1 200 /,
	'upstream retry reaches the backup server');
my @retry = grep { length } split /\n/, $t->read_file('retry.log');
is(scalar @retry, 2, 'each upstream contact produces one log entry');
like($retry[0], qr{^/retry\|retry\|502$},
	'failed upstream contact is logged');
like($retry[1], qr{^/retry\|retry\|502, 200$},
	'successful retry contact is logged');

my ($plain, $combined) = ('', '');
for my $case (
	['one', 'yes', '1', 1],
	['zero', 'yes', '0', 0],
	['empty', 'yes', '', 0],
	['miss', 'no', '1', 1],
	['zeros', 'yes', '00', 1],
	['word', 'yes', 'false', 1],
) {
	my ($id, $selected, $gate, $enabled) = @$case;
	like(response("/if?id=$id&log=$selected&gate=$gate", 8080),
		qr/^HTTP\/1\.1 200 /, "if= request $id succeeds");
	$plain .= "/if|$id|200\n" if $enabled;
	$combined .= "/if|$id|200\n" if $enabled && $selected eq 'yes';
}
$t->stop();
is($t->read_file('if.log'), $plain, 'if= uses standard truth values with expr');
is($t->read_file('when-if.log'), $combined, 'when and if= must both match');

for my $wrapped (0, 1) {
	my $line = 'upstream_log %%TESTDIR%%/invalid.log combined if!=1;';
	$line = "when selected { $line }" if $wrapped;
	$t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    expr selected bool true;
    $line
}
EOF
	my $output = $t->dump_config();
	isnt($?, 0, "if!= is rejected, when=$wrapped");
	like($output, qr/invalid parameter "if!=1"/, 'unsupported parameter diagnostic');
}

###############################################################################

sub response {
	my ($uri, $port) = @_;

	return http("GET $uri HTTP/1.1\x0d\x0a"
		. "Host: localhost\x0d\x0a"
		. "Connection: close\x0d\x0a\x0d\x0a",
		PeerAddr => '127.0.0.1:' . port($port));
}

###############################################################################

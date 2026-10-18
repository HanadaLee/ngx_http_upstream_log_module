#!/usr/bin/perl

# Select the nearest active logging level, before applying per-entry if=.

use strict;
use warnings;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

my @requests = (
    ['/fallback', ['parent']],
    ['/fallback?server=yes', ['server']],
    ['/select?child=yes&gate=1', ['child']],
    ['/select?child=yes&gate=0', []],
    ['/select?child=yes', []],
    ['/select?child=yes&gate=00&second=yes', ['child', 'second']],
    ['/select?second=yes', ['second']],
    ['/select', ['parent']],
    ['/off?child=yes', []],
    ['/off', ['parent']],
    ['/ordered?child=yes', ['before']],
    ['/ordered', ['before', 'after']],
    ['/local?gate=0', []],
    ['/local?gate=1', ['child']],
    ['/nested/deep', ['parent']],
    ['/nested/deep?server=yes', ['server']],
    ['/nested/deep?child=yes', ['child']],
    ['/nested/deep?child=yes&leaf=yes', ['leaf']],
    ['/parent-off/child', []],
    ['/parent-off/child?child=yes', ['off_child']],
    ['/redefine?server=yes', ['parent']],
    ['/only-access?child=yes', ['parent']],
    ['/only-upstream?child=yes', ['only_upstream']],
    ['/redirect?child=yes&gate=1', ['child']],
    ['/retry', ['retry', 'parent']],
    ['/fallback', ['parent']],
);
my @destinations = qw/parent server child second before after leaf off_child
    unused only_upstream retry/;
my $t = Test::Nginx->new()->has(qw/http proxy rewrite
    ngx_expr_module ngx_http_upstream_log_module/)
    ->plan(@requests + @destinations + 2);

my $config = <<'EOF';
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    log_format values '$arg_id';
    access_log %%TESTDIR%%/access-parent.log values;
    expr server_selected str_eq $arg_server yes;
    expr child_selected str_eq $arg_child yes;
    expr second_selected str_eq $arg_second yes;
    expr leaf_selected str_eq $arg_leaf yes;
    expr failed_attempt str_eq $upstream_status 502;
    expr no bool false;
    upstream_log %%TESTDIR%%/upstream-parent.log values;

    upstream retry_backend {
        server 127.0.0.1:8999;
        server 127.0.0.1:8081 backup;
    }
    server {
        listen 127.0.0.1:8081;
        access_log off;
        upstream_log off;
        return 200 ok;
    }
    server {
        listen 127.0.0.1:8080;
        when server_selected { upstream_log %%TESTDIR%%/upstream-server.log values; }

        location /fallback {
            when no { upstream_log %%TESTDIR%%/upstream-unused.log values; }
            proxy_pass http://127.0.0.1:8081;
        }
        location /select {
            when child_selected { upstream_log %%TESTDIR%%/upstream-child.log values if=$arg_gate; }
            when second_selected { upstream_log %%TESTDIR%%/upstream-second.log values; }
            proxy_pass http://127.0.0.1:8081;
        }
        location /off {
            when child_selected { upstream_log off; }
            proxy_pass http://127.0.0.1:8081;
        }
        location /ordered {
            upstream_log %%TESTDIR%%/upstream-before.log values;
            when child_selected { upstream_log off; }
            upstream_log %%TESTDIR%%/upstream-after.log values;
            proxy_pass http://127.0.0.1:8081;
        }
        location /local {
            upstream_log %%TESTDIR%%/upstream-child.log values if=$arg_gate;
            proxy_pass http://127.0.0.1:8081;
        }
        location /nested {
            when child_selected { upstream_log %%TESTDIR%%/upstream-child.log values; }
            proxy_pass http://127.0.0.1:8081;
            location /nested/deep {
                when leaf_selected { upstream_log %%TESTDIR%%/upstream-leaf.log values; }
                proxy_pass http://127.0.0.1:8081;
            }
        }
        location /parent-off {
            upstream_log off;
            proxy_pass http://127.0.0.1:8081;
            location /parent-off/child {
                when child_selected { upstream_log %%TESTDIR%%/upstream-off_child.log values; }
                proxy_pass http://127.0.0.1:8081;
            }
        }
        location /redefine {
            expr server_selected bool false;
            when no { upstream_log %%TESTDIR%%/upstream-unused.log values; }
            proxy_pass http://127.0.0.1:8081;
        }
        location /only-access {
            when child_selected {
                access_log %%TESTDIR%%/access-only_access.log values;
            }
            proxy_pass http://127.0.0.1:8081;
        }
        location /only-upstream {
            when child_selected {
                upstream_log %%TESTDIR%%/upstream-only_upstream.log values;
            }
            proxy_pass http://127.0.0.1:8081;
        }
        location /redirect { rewrite ^ /select last; }
        location /retry {
            when failed_attempt { upstream_log %%TESTDIR%%/upstream-retry.log values; }
            proxy_next_upstream error;
            proxy_next_upstream_tries 2;
            proxy_pass http://retry_backend;
        }
    }
}
EOF

$t->write_file_expand('nginx.conf', $config);
$t->run();

my %expected;
for my $i (0 .. $#requests) {
    my ($uri, $upstream) = @{$requests[$i]};
    $uri .= ($uri =~ /\?/ ? '&' : '?') . "id=$i";
    like(http_get($uri), qr/^HTTP\/1\.1 200 /, "HTTP $uri");
    my $access_sink = $uri =~ m{^/only-access\?} ? 'only_access' : 'parent';
    $expected{"access-$access_sink"} .= "$i\n";
    $expected{"upstream-$_"} .= "$i\n" for @$upstream;
}
$t->stop();

for my $name (@destinations) {
    my $file = "upstream-$name.log";
    my $actual = -e $t->testdir() . "/$file" ? $t->read_file($file) : '';
    is($actual, $expected{"upstream-$name"} || '', "upstream $name inheritance");
}
for my $name (qw/parent only_access/) {
    is($t->read_file("access-$name.log"), $expected{"access-$name"} || '',
        "upstream_log does not change access_log $name");
}

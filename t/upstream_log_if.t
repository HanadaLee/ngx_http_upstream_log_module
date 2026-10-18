#!/usr/bin/perl

# Standard if= remains available with expr; when and if= are ANDed.

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my @cases = (
    ['hit', '1', 1],
    ['hit', '0', 0],
    ['hit', '', 0],
    ['miss', '1', 1],
    ['hit', '00', 1],
    ['hit', 'false', 1],
);
my $t = Test::Nginx->new()->has(qw/http proxy rewrite
    ngx_expr_module ngx_http_upstream_log_module/)->plan(14);

$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    log_format values '$arg_mode|$arg_gate';
    expr selected str_eq $arg_mode hit;

    server {
        listen 127.0.0.1:8080;
        upstream_log %%TESTDIR%%/upstream-plain.log values if=$arg_gate;
        when selected {
            upstream_log %%TESTDIR%%/upstream-when.log values if=$arg_gate;
        }
        location / { proxy_pass http://127.0.0.1:8081; }
    }
    server {
        listen 127.0.0.1:8081;
        return 200 ok;
    }
}
EOF

$t->run();
my ($plain, $combined) = ('', '');
for my $case (@cases) {
    my ($mode, $gate, $enabled) = @$case;
    like(http_get("/?mode=$mode&gate=$gate"), qr/^HTTP\/1\.1 200 /,
        "HTTP mode=$mode gate=$gate");
    $plain .= "$mode|$gate\n" if $enabled;
    $combined .= "$mode|$gate\n" if $enabled && $mode eq 'hit';
}
$t->stop();

is($t->read_file('upstream-plain.log'), $plain, 'upstream standard truth values');
is($t->read_file('upstream-when.log'), $combined, 'upstream when AND if=');

# Check both ordinary and when contexts. Do not accept if!= syntax.
for my $spec (
    ['http', 'upstream_log', '%%TESTDIR%%/invalid.log values'],
) {
    my ($context, $directive, $arguments) = @$spec;
    for my $wrapped (0, 1) {
        my $line = "$directive $arguments if!=1;";
        $line = "when selected { $line }" if $wrapped;
        my $format = "log_format values '\$remote_addr';";
        $t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
daemon off;
events {}
$context {
    $format
    expr selected bool true;
    $line
}
EOF
        my $output = $t->dump_config();
        my $status = $?;
        isnt($status, 0, "$context $directive if!= rejected, when=$wrapped");
        like($output, qr/invalid parameter "if!=1"/,
            "$context $directive reports unsupported parameter");
    }
}

# Standard if= must also remain accepted when no when block is configured.
$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    log_format values '$remote_addr';
    upstream_log %%TESTDIR%%/only-upstream-if.log values if=0;
}
EOF
my $output = $t->dump_config();
is($?, 0, 'if= configuration without any when is accepted');
unlike($output, qr/\[emerg\]/, 'if= does not require a when definition');

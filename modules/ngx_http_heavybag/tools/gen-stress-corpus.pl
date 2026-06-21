#!/usr/bin/env perl
#
# gen-stress-corpus.pl -- derive a COMMITTED, bit-reproducible stress URL list
# from the pinned replay corpus (corpus/replay-vectors.jsonl, threat-model \xc2\xa76 step 0).
#
# DETERMINISM IS THE WHOLE POINT. There is NO randomness anywhere:
#   * attack URIs are the top-N vectors ranked by (count DESC, uri ASC) -- a total
#     order, so ties never reorder between runs;
#   * benign URIs are a fixed inline anchor set, inserted at a fixed cadence;
#   * the output byte stream is a pure function of (input file, TOP_N, BENIGN_EVERY).
# Re-running with the same input + params yields a byte-identical stress-urls.txt,
# so the committed file IS the contract: everyone replays the exact same load.
#
# The output is consumed two ways, both of which ignore '#'-prefixed lines:
#   * h2load -- fed the bare paths as request targets (grep -v '^#');
#   * wrk2   -- tests/stress/stress.lua reads the same file and cycles the paths.
#
# Usage:
#   perl gen-stress-corpus.pl [--in FILE] [--out FILE] [--top-n N] [--benign-every K]
# Defaults: --in corpus/replay-vectors.jsonl  --out corpus/stress-urls.txt
#           --top-n 100  --benign-every 5
#
# Run from anywhere; paths default relative to the tests/ dir two levels up, matching
# how the other tools/ scripts resolve the corpus. Override with HEAVYBAG_ROOT.

use strict;
use warnings;
use JSON::PP;
use Getopt::Long;
use File::Basename;

# --- resolve the tests/corpus dir relative to this script (tools/ -> tests/) ---
my $root   = $ENV{HEAVYBAG_ROOT} // '/mnt/nvme/imaginarium/openresty';
my $corpus = "$root/modules/ngx_http_heavybag/tests/corpus";

my $in          = "$corpus/replay-vectors.jsonl";
my $out         = "$corpus/stress-urls.txt";
my $top_n       = 100;
my $benign_every = 5;

GetOptions(
    'in=s'           => \$in,
    'out=s'          => \$out,
    'top-n=i'        => \$top_n,
    'benign-every=i' => \$benign_every,
) or die "usage: $0 [--in FILE] [--out FILE] [--top-n N] [--benign-every K]\n";

die "top-n must be >= 1\n"        if $top_n < 1;
die "benign-every must be >= 1\n" if $benign_every < 1;

# Fixed benign anchor set. '/' maps to the static index in the stress sandbox
# html root (served 200, WAF verdict=allowed); the rest are common static probes
# that the scanner/path matchers never flag, so they always land in http_allowed.
# This list is ORDERED and cycled deterministically -- never sorted, never shuffled.
my @BENIGN = ('/', '/index.html', '/robots.txt', '/favicon.ico');

# --- load + rank ------------------------------------------------------------
my $json = JSON::PP->new->utf8;
open my $fh, '<', $in or die "cannot open $in: $!\n";

my %seen;        # uri -> highest count seen (collapse duplicate URIs)
while (<$fh>) {
    chomp;
    next unless /\S/;
    my $d = eval { $json->decode($_) } or next;
    my $uri   = $d->{uri};
    my $count = $d->{count} // 1;
    next unless defined $uri && length $uri;

    # GET stress targets must be origin-form absolute paths: drop asterisk-form
    # ('*'), authority-form, and any vector whose URI is not rooted at '/'. These
    # are scan artifacts (OPTIONS *, CONNECT host:port) that make no sense as a
    # replayed GET target and would confuse h2load arg parsing.
    next unless $uri =~ m{^/};

    # A stress URL list must be one-target-per-line and shell/HTTP-safe: drop any
    # URI carrying whitespace or control bytes (they would corrupt the line-based
    # file and break h2load arg-splitting). The replay corpus is already filtered
    # to 'METHOD SP URI SP HTTP/x.y', so this only trims pathological tails.
    next if $uri =~ /[\x00-\x20\x7f]/;

    $seen{$uri} = $count if !exists $seen{$uri} || $count > $seen{$uri};
}
close $fh;

# Total order: count DESC, then uri ASC. Deterministic for ties.
my @ranked = sort {
    $seen{$b} <=> $seen{$a}
        or
    $a cmp $b
} keys %seen;

@ranked = @ranked[0 .. $top_n - 1] if @ranked > $top_n;

# --- interleave benign at a fixed cadence -----------------------------------
# Every BENIGN_EVERY-th emitted attack URI is preceded by one benign URI, cycling
# the benign anchors in order. Deterministic placement, deterministic anchor pick.
my @lines;
my $bi = 0;
for (my $i = 0; $i < @ranked; $i++) {
    if ($i % $benign_every == 0) {
        push @lines, $BENIGN[$bi % @BENIGN];
        $bi++;
    }
    push @lines, $ranked[$i];
}

my $n_attack = scalar @ranked;
my $n_benign = $bi;

# --- write ------------------------------------------------------------------
open my $ofh, '>', $out or die "cannot open $out for write: $!\n";
print $ofh "# heavybag stress URL corpus -- GENERATED, do not hand-edit.\n";
print $ofh "# source: ", basename($in), "  top_n=$top_n  benign_every=$benign_every\n";
print $ofh "# attack_uris=$n_attack benign_uris=$n_benign total=", scalar(@lines), "\n";
print $ofh "# regenerate: perl modules/ngx_http_heavybag/tools/gen-stress-corpus.pl\n";
print $ofh "# consumers strip '#' lines (h2load via grep -v, wrk2 via stress.lua).\n";
for my $u (@lines) {
    print $ofh $u, "\n";
}
close $ofh;

print STDERR "wrote $out: $n_attack attack + $n_benign benign = ",
             scalar(@lines), " lines\n";

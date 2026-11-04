---
name: build-matrix
type: runbook
status: active
title: Build-portability matrix (heavybag_build_matrix)
description: What run-build-matrix.sh asserts, its configure permutations, tree bootstrap, the expected --without-pcre abort, the heavybag_module self-heal, and the dependency pins with the per-nginx-version rebuild rule.
sources:
  - modules/ngx_http_heavybag/tests/run-build-matrix.sh
  - modules/ngx_http_heavybag/tests/run-build-matrix.sh:build_tree
  - modules/ngx_http_heavybag/tests/run-build-matrix.sh:sym_tree
  - modules/ngx_http_heavybag/tests/run-build-matrix.sh:bootstrap
  - cmake/Tests.cmake
  - CMakeLists.txt
  - cmake/Versions.cmake
verified:
  commit: 35d6bb3
  date: 2026-11-04
links:
  - overview
  - qa-test-matrix
  - qa-findings
  - threat-intel-sources
---

# Build-portability matrix (heavybag_build_matrix)

The build matrix is the regression net for heavybag's build portability. It
rebuilds the dynamic module against a set of nginx `./configure` permutations
and checks what each resulting `.so` exports and links against
`modules/ngx_http_heavybag/tests/run-build-matrix.sh`. It catches the shipped
build fixes that only break under a non-default configure surface: the
reason-filter declaration living outside `#if (NGX_HTTP_SSL)`, the stream
sources gated in `config` on `$STREAM`, and the JA4 SSL extractor wrapped in
`#if (NGX_HTTP_SSL)` `modules/ngx_http_heavybag/tests/run-build-matrix.sh`,
`modules/ngx_http_heavybag/config`.

## Running it

It is registered as the CTest test `heavybag_build_matrix` under the `build`
label `cmake/Tests.cmake`. It needs the CMake super-build done first
(`cmake --build build -j`) but no running nginx `cmake/Tests.cmake`:

- `ctest --test-dir build -R heavybag_build_matrix` (or `-L build`), or
- `bash modules/ngx_http_heavybag/tests/run-build-matrix.sh` directly.

Preflight: the script needs the extracted nginx source tree under
`build/nginx_ext-prefix/src/nginx_ext` and reads the canonical configure
arguments live from `sandbox/sbin/nginx -V`. If either is missing it exits 2,
which CTest reports as SKIPPED rather than failed (`SKIP_RETURN_CODE 2`)
`modules/ngx_http_heavybag/tests/run-build-matrix.sh`, `cmake/Tests.cmake:heavybag_add_test`.

It rebuilds **module-only** (`make -f <builddir>/Makefile modules`). It does not
rerun nginx's full build, so it avoids the OpenSSL-rebuild trap
`modules/ngx_http_heavybag/tests/run-build-matrix.sh:build_tree`.

## What it asserts

For every buildable permutation,
`modules/ngx_http_heavybag/tests/run-build-matrix.sh:build_tree` checks that:

- `make modules` exits 0 **with zero `warning:` lines** (the build is `-Werror`);
- `ngx_http_heavybag_module.so` is produced.

Then `modules/ngx_http_heavybag/tests/run-build-matrix.sh:sym_tree` inspects the
`.so` and checks that:

- `ngx_http_heavybag_module` is exported by every variant (`nm -D`);
- `ngx_stream_heavybag_module` is exported by every variant **except**
  `objs-nostream`, where it must be absent;
- the `objs-nossl` `.so` has **zero undefined `SSL_*` symbols**;
- the `DT_NEEDED` libcrypto entry (`readelf -d`) is present **iff** nginx was
  built without OpenSSL (`objs-nossl`), and absent on every SSL variant.
  The geo reader verifies the `location.db` signature with libcrypto
  `modules/ngx_http_heavybag/src/heavybag_geo.c:ngx_http_heavybag_geo_verify`.
  The module `config` adds `-lcrypto` only when `USE_OPENSSL` is not `YES`
  (without OpenSSL the EVP/PEM symbols would be undefined at `dlopen`); on SSL
  builds the symbols resolve from the nginx executable's embedded OpenSSL, and
  a `DT_NEEDED` entry would load a second (system) libcrypto into the process.
  The undefined `EVP_*` symbols stay in `.dynsym` either way.

Exit 0 means every buildable permutation built clean and every symbol
assertion held. The final `RESULT` line prints the pass/fail/skip tally
`modules/ngx_http_heavybag/tests/run-build-matrix.sh`.

## The permutation set

Each permutation is a separate `--builddir` tree under the nginx source. The
variant arguments are a `sed` transform of the canonical configure arguments
`modules/ngx_http_heavybag/tests/run-build-matrix.sh`:

| builddir | derived from canonical by | stream module expected |
|---|---|---|
| `objs` | nothing: the canonical CMake tree (SSL + stream + http_v2 + http_v3 + mail) | present |
| `objs-nossl` | stripping `--with-http_ssl_module`, `--with-http_v3_module` (QUIC also needs OpenSSL), `--with-stream_ssl_preread_module`, `--with-mail_ssl_module` and `--with-openssl=…` | present (plus the zero-`SSL_*` check) |
| `objs-nostream` | stripping `--with-stream_realip_module` and `--with-stream_ssl_preread_module` first, then `--with-stream` (` --with-stream` is their common prefix) | **absent** |
| `objs-nov2` | stripping `--with-http_v2_module` | present |
| `objs-nov3` | stripping `--with-http_v3_module` | present |
| `objs-mail` | the canonical args unchanged (mail is already on), which cross-checks that mail does not interfere | present |
| `objs-nopcre` | stripping `--with-pcre=…` / `--with-pcre-jit` and adding `--without-pcre` | n/a: expected configure abort |

The canonical flag set itself is defined once in `CMakeLists.txt`
(`_NGINX_CONFIGURE_ARGS`), and the matrix never hard-codes it
`CMakeLists.txt`.

## Tree bootstrap: only `objs/` is required

Only the canonical `objs/` tree, which CMake creates, is required. If it has no
`Makefile`, that is a hard failure: run the CMake build first. Every other tree
that is missing is bootstrapped on the spot. This includes `objs-nossl` and
`objs-nostream` since commit `2e4e406`, after an nginx version bump
re-extracted the source and wiped them. Bootstrapping means
`./configure <transformed args> --builddir=<dir>` followed by the generated
OpenSSL `ssl.h` touch-guard, so the next `make` does not start a doomed full
OpenSSL rebuild `modules/ngx_http_heavybag/tests/run-build-matrix.sh:bootstrap`,
`CMakeLists.txt`. Each tree's configure and build output goes to
`<builddir>.configure.log` / `<builddir>.modules.log` in the nginx source tree.
Read those when an entry FAILs.

## `objs-nopcre`: an expected abort

nginx's built-in `http_rewrite` module hard-requires PCRE, so
`./configure --without-pcre` aborts before any heavybag source is compiled. The
matrix treats that as the **correct** outcome. It passes when
`objs-nopcre.configure.log` contains `requires the PCRE library` **and** no
`objs-nopcre/Makefile` was produced. Any other outcome fails
`modules/ngx_http_heavybag/tests/run-build-matrix.sh`. This is a clean
configure-time diagnostic, not a heavybag portability defect. heavybag itself
requires PCRE2 at build time (see [[overview]]).

## Afterwards: top-level Makefile clobber and self-heal

Every `./configure --builddir=…` run rewrites nginx's **top-level** `Makefile`
to point at that variant's tree. The aborted `--without-pcre` configure leaves
it as a stub with no `modules` rule, so after the matrix a plain `make modules`
in the nginx source dies with "No rule to make target 'modules'" `CMakeLists.txt`.

The fast-iteration target `cmake --build build --target heavybag_module`
heals itself. Its generated script first probes `make -n modules`. If the
probe fails, it re-runs the canonical `./configure` with the shared
`_NGINX_CONFIGURE_ARGS`, runs the `ssl.h` touch-guard, and then builds and
copies the `.so` into `sandbox/modules/` `CMakeLists.txt:heavybag_module`. You
only pay for that re-configure after a matrix run. Ordinary iterations skip
straight to the build. As always, a rebuilt `.so` needs a full nginx stop and
start, because `nginx -s reload` does not reload module code `CMakeLists.txt`.

## Dependency pins and nginx upgrades

The super-build pins nginx 1.31.8, OpenSSL 3.5.9 and PCRE2 10.49 (raised from
1.31.3 / 3.5.7 / 10.47 for the advisories in [[threat-intel-sources]] §8)
`cmake/Versions.cmake`. Bumping one is a one-line edit of its `PKG_*_VERSION`
there; the tarball SHA256 is resolved on the next configure
`cmake/Versions.cmake:resolve_sha256`.

**Rebuild the module for every nginx version.** The `.so` is ABI-bound to the
nginx it was built against: nginx 1.31.5 changed the layout of
`ngx_http_core_loc_conf_t` without padding (researched 2026-11-04), so a module
built against another nginx version must not be loaded. A version bump
therefore means a full CMake build plus this matrix, never a copied `.so`.
The source audit for the 1.31.8 bump: the module uses no `ngx_http_script_*`,
`ngx_json_*`, `ngx_http_upstream_state_t` or `r->main->blocked`, and of
`ngx_http_core_loc_conf_t` it sets only the `handler` field, in the
`waf_mail_auth` and `waf_status` setters
`modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c:ngx_http_heavybag_set_mail_auth`,
`modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c:ngx_http_heavybag_set_status`.

nginx behaviour changes between 1.31.3 and 1.31.8 that an edge config can
notice (researched 2026-11-04, not code-verified):

- `Host` / `:authority` is always sent to the backend. `proxy_set_header Host ""`
  no longer drops the header: it yields `$proxy_host`.
- `working_directory` is resolved relative to the prefix, and an invalid path
  is rejected at config load instead of at run time.
- HTTP/2 uses the RFC 9218 priority scheme.

The phase that introduced the matrix, and the findings it nets, are recorded in
[[qa-test-matrix]] and [[qa-findings]].

# ============================================================================
# cmake/Tests.cmake -- register the heavybag test harnesses as CTest tests.
#
# The portable entry point for the QA test-matrix campaign (docs/qa-campaign.md).
# Each test is a THIN CTest wrapper around the committed bash harness under
# modules/ngx_http_heavybag/tests/ -- the harness stays the single source of
# truth, CMake/CTest is just the portable launcher (pass/fail summary, labels,
# parallelism, JUnit/XML export for CI, timeouts).
#
# Usage (after a normal build produces the sandbox nginx + deployed .so):
#     cmake --build build -j
#     ctest --test-dir build                 # run everything
#     ctest --test-dir build -L integration  # only the live-nginx harnesses
#     ctest --test-dir build -L unit         # only the standalone unit suite
#     ctest --test-dir build -R config       # by name regex
#     ctest --test-dir build -j8             # parallel (nginx-bound tests are
#                                            #   still serialised by a resource lock)
#   or the convenience wrapper:
#     cmake --build build --target check
#
# A harness that exits 2 (its preflight detected the sandbox is not built yet)
# is reported by CTest as SKIPPED, not failed -- so `ctest` before `cmake --build`
# is harmless. The unit + build-matrix tests do not need a running nginx; the
# rest load the deployed sandbox/modules/.so against a live master they start on
# loopback-only 28xxx ports.
# ============================================================================

find_program(BASH_PROGRAM bash)
if(NOT BASH_PROGRAM)
  message(WARNING "bash not found -- heavybag CTest harnesses will NOT be registered")
  return()
endif()

set(_HB_TESTS ${CMAKE_SOURCE_DIR}/modules/ngx_http_heavybag/tests)

# heavybag_add_test(<name> <script-rel-to-tests-dir>
#                   [TIMEOUT <seconds>] [LABELS <l1;l2>] [NGINX_BOUND])
#
# NGINX_BOUND tests start a real nginx master on fixed ports and share the
# sandbox .so/logs, so they take a RESOURCE_LOCK and never run concurrently
# with each other (even under `ctest -jN`).
function(heavybag_add_test name script)
  cmake_parse_arguments(T "NGINX_BOUND" "TIMEOUT" "LABELS;ENV" ${ARGN})
  if(NOT EXISTS ${_HB_TESTS}/${script})
    message(WARNING "heavybag test harness missing, skipping registration: ${script}")
    return()
  endif()
  if(NOT T_TIMEOUT)
    set(T_TIMEOUT 600)
  endif()
  # make the harnesses relocatable: they read ROOT from this env (falling back
  # to the historical /mnt path when run by hand without it). Extra per-test ENV
  # (e.g. LIMIT for the replay sweep) is appended to the same property list.
  set(_env "HEAVYBAG_ROOT=${CMAKE_SOURCE_DIR}")
  if(T_ENV)
    list(APPEND _env ${T_ENV})
  endif()
  add_test(NAME ${name}
           COMMAND ${BASH_PROGRAM} ${_HB_TESTS}/${script}
           WORKING_DIRECTORY ${_HB_TESTS})
  set_tests_properties(${name} PROPERTIES
    LABELS           "${T_LABELS}"
    TIMEOUT          ${T_TIMEOUT}
    SKIP_RETURN_CODE 2
    ENVIRONMENT      "${_env}")
  if(T_NGINX_BOUND)
    set_tests_properties(${name} PROPERTIES RESOURCE_LOCK heavybag_sandbox)
  endif()
endfunction()

# --- standalone unit suite (compiles its own gcc binaries, no nginx) ---------
heavybag_add_test(heavybag_unit         unit/run-unit-tests.sh  LABELS "unit"                TIMEOUT 600)

# --- same suite under gcov instrumentation (opt-in measurement, additive) ----
# Mirrors heavybag_unit but flips HEAVYBAG_COVERAGE=1 so each TU is built
# --coverage -O0 and a per-source line/branch report is printed. heavybag_unit
# stays THE fast gate; this one is for measuring, not gating (-O0 + gcov is
# slower, hence the wider timeout). Run it explicitly: ctest -L coverage.
heavybag_add_test(heavybag_unit_coverage unit/run-unit-tests.sh LABELS "unit;coverage" TIMEOUT 900 ENV "HEAVYBAG_COVERAGE=1")

# --- build-portability matrix (rebuilds the ./configure permutation trees) ---
heavybag_add_test(heavybag_build_matrix run-build-matrix.sh     LABELS "build"               TIMEOUT 1800)

# --- live-nginx integration + runtime (need the built sandbox + deployed .so) -
heavybag_add_test(heavybag_config       run-config-tests.sh     LABELS "integration;config"  TIMEOUT 600  NGINX_BOUND)
heavybag_add_test(heavybag_protocol     run-protocol-tests.sh   LABELS "integration"         TIMEOUT 600  NGINX_BOUND)
heavybag_add_test(heavybag_stat         run-stat-tests.sh       LABELS "integration"         TIMEOUT 900  NGINX_BOUND)
heavybag_add_test(heavybag_regression   run-regression-tests.sh LABELS "integration"         TIMEOUT 600  NGINX_BOUND)
heavybag_add_test(heavybag_runtime      run-runtime-tests.sh    LABELS "integration;runtime" TIMEOUT 600  NGINX_BOUND)

# --- mail auth_http content-handler deep-fuzz (the critic's un-probed SMTP) ---
# Drives the 8 fedetlen edges of heavybag_authhttp.c (missing/garbage/IPv6/multi
# Client-IP, untrusted-peer spoof, geo/asn/flag verdict, missing backend, for_geo
# rate). Geo edges self-validate ground truth via reference/geolookup.c and SKIP
# if geodb is absent/drifted; the #5 edges SKIP on a loopback-only host.
heavybag_add_test(heavybag_mailauth     run-mailauth-fuzz.sh    LABELS "integration"         TIMEOUT 600  NGINX_BOUND)

# --- reputation verdict-precedence deep-fuzz (the critic's un-probed order) ---
# Builds reputation_check collisions (one IP matching blocklist+flag+asn+geo at
# once) and asserts the first-match-wins order, each backed by single-source
# controls. Geo-centric: SKIPs (exit 2) if geodb/oracle is absent or drifted.
heavybag_add_test(heavybag_repprec      run-reputation-precedence.sh LABELS "integration"    TIMEOUT 600  NGINX_BOUND)

# --- JA4<->UA spoof deep-fuzz / "self-swap" (the critic's un-probed matrix) ---
# Drives the full {fam_ja4} x {fam_ua} grid of ngx_http_heavybag_ua_spoof_eval
# (ja4.list reloads map the live curl JA4 to each family) + the cidr_signal
# fake-verified-bot path. Needs OpenSSL curl + the deployed .so; SKIPs (exit 2)
# if the live JA4 is unreadable.
heavybag_add_test(heavybag_spoof        run-spoof-fuzz.sh       LABELS "integration"         TIMEOUT 600  NGINX_BOUND)

# --- detect-mode replay (FP gate is the pass/fail; coverage sweep capped) -----
# Exit 0 iff the false-positive gate holds (every baseline path returns reason=none
# and all would_block deltas are 0); the main coverage replay is bounded by LIMIT.
heavybag_add_test(heavybag_replay       run-replay-tests.sh     LABELS "integration;replay"  TIMEOUT 900  NGINX_BOUND  ENV "LIMIT=200")

# --- stress / load campaign (docs/stress-campaign.md) -------------------------
# heavybag_stress is the SMOKE gate: run-stress-tests.sh --quick drives a ~10s/
# scenario load and the pass/fail is the S3 counter invariant
# (d(http_requests_total)==d(allowed)+sum d(blocked), and the stream analogue).
# It needs h2load (nghttp2); without it the harness exits 2 -> CTest SKIPPED, so
# `ctest` on a host without the load tools is harmless. NGINX_BOUND: it starts a
# real master on the 283xx band and shares the sandbox .so, so it takes the
# sandbox resource lock like the other live harnesses.
heavybag_add_test(heavybag_stress       run-stress-tests.sh     LABELS "integration;stress"   TIMEOUT 900  NGINX_BOUND  ENV "HB_STRESS_MODE=quick")

# heavybag_soak is OPT-IN: a bare `ctest` SKIPs it instantly (the harness exits 2
# unless HB_STRESS_SOAK_OPT_IN=1). Run it deliberately for a long stability pass:
#   HB_STRESS_SOAK_OPT_IN=1 HB_SOAK_DUR=3600 ctest --test-dir build -R heavybag_soak
# The pass/fail is the RSS least-squares slope leak gate.
heavybag_add_test(heavybag_soak         run-stress-tests.sh     LABELS "integration;soak"     TIMEOUT 14400 NGINX_BOUND  ENV "HB_STRESS_MODE=soak")

# --- honeypot-D offline ASN/geo analysis (no nginx; SKIPs if inputs absent) ---
# Pure read-only analysis pipeline: builds reference/geolookup.c, extracts the
# per-IP volume feed, joins it with geo. Exits 2 (-> CTest SKIPPED) when the raw
# access log / geo db are not present on this host.
heavybag_add_test(heavybag_honeypot     run-honeypot-d.sh       LABELS "analysis"            TIMEOUT 600)

# --- reference-oracle build smoke (compiles reference/*.c; asserts no behaviour)
heavybag_add_test(heavybag_oracle_build run-oracle-build.sh     LABELS "build"               TIMEOUT 300)

# --- convenience: `cmake --build build --target check` == ctest --------------
add_custom_target(check
  COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure --test-dir ${CMAKE_BINARY_DIR}
  COMMENT "Running the heavybag CTest suite (ctest --output-on-failure)")

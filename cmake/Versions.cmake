# Versions.cmake — version pins and download URLs for the super-build. Kept
# separate from CMakeLists.txt so bumping a dependency is a ONE-LINE change:
# edit the PKG_*_VERSION below and reconfigure. Override any PKG_* on the
# command line with -D.
#
# SHA256 hashes are resolved AUTOMATICALLY: on the first configure for a given
# version the tarball is fetched once into build/dl-cache/, hashed, and the
# digest reused on every later reconfigure (no re-download, no hash pasted by
# hand). This just automates the manual "download it, trust it, sha256sum it"
# step. To pin a hash explicitly (audited / air-gapped build) pass
# -D<DEP>_SHA256=<hex> — an explicit 64-hex pin always wins over auto-resolve.

# These are the source of truth: editing a version here is picked up on the
# next reconfigure even in an existing build/ tree. A plain `set(... CACHE ...)`
# would NOT — an already-cached value shadows the edited default — which defeats
# the "just change the version" promise. So the file default wins unless the
# var is explicitly overridden with -DPKG_*_VERSION=… (which lands in the cache,
# is DEFINED, and therefore sticks until the cache is cleared).
if(NOT DEFINED PKG_OPENSSL_VERSION)
  set(PKG_OPENSSL_VERSION 3.5.9)
endif()
if(NOT DEFINED PKG_NGINX_VERSION)
  set(PKG_NGINX_VERSION 1.31.8)
endif()
if(NOT DEFINED PKG_ZLIBNG_VERSION)
  set(PKG_ZLIBNG_VERSION 2.3.3)
endif()
if(NOT DEFINED PKG_PCRE2_VERSION)
  set(PKG_PCRE2_VERSION 10.49)
endif()

# --- download URLs ---------------------------------------------------------
set(ZLIBNG_URL  "https://github.com/zlib-ng/zlib-ng/archive/refs/tags/${PKG_ZLIBNG_VERSION}.tar.gz")
set(NGINX_URL   "https://nginx.org/download/nginx-${PKG_NGINX_VERSION}.tar.gz")
set(OPENSSL_URL "https://github.com/openssl/openssl/releases/download/openssl-${PKG_OPENSSL_VERSION}/openssl-${PKG_OPENSSL_VERSION}.tar.gz")
set(PCRE2_URL   "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${PKG_PCRE2_VERSION}/pcre2-${PKG_PCRE2_VERSION}.tar.gz")

# --- SHA256 hashes — empty means "auto-resolve"; -D pins an explicit digest -
set(ZLIBNG_SHA256  "" CACHE STRING "zlib-ng tarball SHA256 (empty = auto-resolve)")
set(NGINX_SHA256   "" CACHE STRING "nginx tarball SHA256 (empty = auto-resolve)")
set(OPENSSL_SHA256 "" CACHE STRING "OpenSSL tarball SHA256 (empty = auto-resolve)")
set(PCRE2_SHA256   "" CACHE STRING "PCRE2 tarball SHA256 (empty = auto-resolve)")

# resolve_sha256(<url> <cache-filename> <out-var>)
#   If <out-var> already holds a 64-hex digest (an explicit -D pin), keep it.
#   Otherwise download <url> once into build/dl-cache/<cache-filename>, compute
#   its SHA256, and publish the digest into the caller's scope so the
#   ExternalProject URL_HASH below can verify the extract against it. The
#   cached tarball is reused across reconfigures, so the fetch happens exactly
#   once per version.
function(resolve_sha256 url cache_name out_var)
  set(_cur "${${out_var}}")
  if(_cur MATCHES "^[0-9a-fA-F]{64}$")
    return()  # explicit pin — leave it untouched
  endif()
  set(_cache_dir "${CMAKE_BINARY_DIR}/dl-cache")
  set(_cache_file "${_cache_dir}/${cache_name}")
  if(NOT EXISTS "${_cache_file}")
    message(STATUS "Versions: fetching ${url} to resolve its SHA256")
    file(MAKE_DIRECTORY "${_cache_dir}")
    file(DOWNLOAD "${url}" "${_cache_file}" STATUS _st TLS_VERIFY ON)
    list(GET _st 0 _code)
    if(NOT _code EQUAL 0)
      list(GET _st 1 _msg)
      file(REMOVE "${_cache_file}")
      message(FATAL_ERROR "Versions: download failed for ${url}: ${_msg}")
    endif()
  endif()
  file(SHA256 "${_cache_file}" _hash)
  set(${out_var} "${_hash}" PARENT_SCOPE)
  message(STATUS "Versions: ${cache_name} SHA256=${_hash}")
endfunction()

resolve_sha256("${ZLIBNG_URL}"  "zlib-ng-${PKG_ZLIBNG_VERSION}.tar.gz"  ZLIBNG_SHA256)
resolve_sha256("${NGINX_URL}"   "nginx-${PKG_NGINX_VERSION}.tar.gz"     NGINX_SHA256)
resolve_sha256("${OPENSSL_URL}" "openssl-${PKG_OPENSSL_VERSION}.tar.gz" OPENSSL_SHA256)
resolve_sha256("${PCRE2_URL}"   "pcre2-${PKG_PCRE2_VERSION}.tar.gz"     PCRE2_SHA256)

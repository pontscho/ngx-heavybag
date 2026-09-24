/*
 * ngx_http_heavybag_module - SMTP auth_http endpoint
 *
 * Content handler for an internal HTTP location that speaks the ngx_mail
 * auth_http protocol. ngx_mail performs an auth_http GET before proxying
 * an SMTP/IMAP/POP3 session and forwards the real session peer address in
 * the Client-IP request header. The handler runs the shared
 * ngx_http_heavybag_reputation_check() on that address and answers in the
 * auth_http dialect:
 *
 *     allow -> "Auth-Status: OK" + Auth-Server/Auth-Port (the backend MTA
 *              from waf_mail_backend)
 *     deny  -> "Auth-Status: <reason>" (ngx_mail turns this into an SMTP
 *              5xx with the configured/default error code)
 *
 * One verdict function, two heads: this is the SMTP head; the HTTP
 * PREACCESS phase in ngx_http_heavybag_module.c is the other.
 *
 * Client-IP is NOT trusted on the strength of the transport. The forwarded
 * address is honoured only when the caller authenticates itself with
 * `X-WAF-Key: <waf_mail_trusted_secret>` over a loopback/unix connection;
 * otherwise the real connection peer is judged (fail-closed). Operator setup:
 *
 *     http { ... location = /waf-mail-auth {
 *                waf_mail_auth;
 *                waf_mail_trusted_secret  <token>;
 *            } }
 *     mail { auth_http         127.0.0.1:8081/waf-mail-auth;
 *            auth_http_header  X-WAF-Key "<token>"; }
 *
 * The head is also a first-class citizen of the exported counter invariant
 * requests_total == allowed + sum(blocked); it reuses the http_* counters.
 * Both models are spelled out at the top of heavybag_authhttp.c.
 */

#ifndef _HEAVYBAG_AUTHHTTP_H_INCLUDED_
#define _HEAVYBAG_AUTHHTTP_H_INCLUDED_


#include "ngx_http_heavybag.h"


/* Content handler installed on a location by the waf_mail_auth directive. */
ngx_int_t ngx_http_heavybag_authhttp_handler(ngx_http_request_t *r);


#endif /* _HEAVYBAG_AUTHHTTP_H_INCLUDED_ */

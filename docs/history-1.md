---
name: history-1
type: analysis
status: draft
title: Session Checkpoint / Work History (S1–S18)
description: Cross-session work-log and decision dump. Candidate for removal — git history is authoritative (see PROPOSE-DELETE).
verified:
  commit: 7a935b0
  date: 2026-06-21
links:
  - overview
---
# Session Checkpoint

**Last updated:** 2026-06-15 (local, S18)
**Branch:** main (git repo)
**Working directory:** /mnt/nvme/imaginarium/openresty
**Session count:** 18
**User note:** S18 (2026-06-15): **GAP-LOOP ITERACIO 2 (config/IaC + appliance fingerprints) LESZALLITVA + BEKOMMITOLVA (`cf244cb`, UJ commit, NEM amend).** A partner a harom karbantartasi iranyt valasztotta (stale-fix + tovabbi gap-loop + scanners.list bovites), a honeypot D-t kihagytuk. **Stale-fix:** a §6.B mar az S17-ben `(done)` lett -> NO-OP. **scanners.list bovites** (mind 404, blend-in): (a) config/IaC/secret-leak BROAD-EXT (partner AskUserQuestion: `^/.*\.ya?ml$`, `^/.*\.properties$`, `^/.*\.tfstate`, `^/.*\.tfvars$`) + ~30 enumeralt .json/dotfile secret-store (blankett .json KIHAGYVA a /app.json baseline miatt); (b) Symfony `/debug/default/view`; (c) generikus .php kiterjesztve `^/.*\.php[0-9]?($|[/.~:])`-re (.phpN webshell + IIS `.php::$DATA`/`.php~`/`.php.old` source-leak) + bare `^/phpinfo`; (d) appliance/VPN/RCE fingerprintek (Citrix WPnBr.dll, Telerik, GPON, Cisco /+CSCOL+/, SAP metadatauploader, D-Link getuser, Pulse /dana-{na,cached}/, F5 mgmt/tm/util/bash, SonicWall, MobileIron mifs, ColdFusion CFIDE, Sitecore, RDWeb, evox/about, parastable, etc/passwd). **Generikus szotar-tail KIHAGYVA** (partner AskUserQuestion: /login,/home,/admin,/test... prodban legit lehet). B FP-gate PASS (broad-ext NEM fog baseline-t); coverage uncatalogued 21.6->35.3%, appliance 100%, php 99.9%, secret_vcs 99.8%. C re-freeze 38,905->40,614 ({404:40,573 403:146 444:55}; 403/444 BYTE-AZONOS, csak 404 nott). 9/9 frozen-match; unit 6/6 + stat 131/131 valtozatlan; NINCS .c valtozas (listak hot-reload). HEAD origin/main elott **2** commit (`a1bda45`+`cf244cb`); push = PARTNER. || S17 (2026-06-15): **GAP-LOOP (honeypot §6 A) + §3.1 + misc secret-leaks LESZALLITVA + BEKOMMITOLVA (`a1bda45`, amend).** scanners.list bovites: generikus `.php` catch-all (php 41.6->99.2%, phpadmin 15->98.5%), wlwmanifest.xml (wp 89->99.5%), /bin/sh (shellshock; a melyek 400-on a parsernel, §4), Fortinet /remote/login, Cisco /+cscoe+/ (a kommentelt jelolt elesitve), nmap Trinity, /hello.world; + credential/config/infra-leak cluster (aws/credentials, /credentials, *.env, secrets.json, appsettings.json, /env, Docker /containers/json, /server-status, /druid/; uncatalogued 14.1->21.6%). args.list: php://input 444. **AKCIO-FLIP:** a scanner_lookup precedencia 404>403>444, ezert ~46 phpmyadmin/pma *.php most 404 (volt 403) -- blokkolva marad, elvegyul a 404-ekben; a phpmyadmin/pma KONYVTAR-probe-ok 403 maradnak. B FP-gate PASS; C fixture re-frozen 21,263->38,905 ({404:38,864 403:146 444:55}); run-regression-tests.sh 9/9 100% frozen-match; unit 6/6 + stat 131/131 valtozatlan; NINCS .c valtozas (listak hot-reload). HEAD `a1bda45` origin/main (=`2f0c18e`) elott 1 commit; az S16 9 commitja idokozben FELKERULT. PUSH = PARTNER. A KOVETKEZO: partner dont (honeypot D / tovabbi gap-loop / scanners.list bovites). || S16 (2026-06-15): **HONEYPOT C LESZALLITVA + BEKOMMITOLVA (`2f0c18e`).** Enforce-modu, bekommitolt regresszios fixture + harness. 5 artifact egy logikai commitban: `replay-client.pl --enforce` (friss Connection:close socket/keres + first-byte 444-probe; detect byte-azonos), `waf-regression-test.conf` (dedikalt 283xx, detect+enforce vhost-par dimenziónkent, vhostonkent 1 matcher, PREACCESS-izolacio), `freeze-regression-fixture.pl` (ketpasszos generator: detect->reason, enforce->status, dedup uri/value, covered-subset enforce-pass), `regression-vectors.jsonl` (21,263 path/args) + `regression-headers.jsonl` (160 ua/referer/cookie/fakebot) frozen verdiktekkel (`expected_status` in {404:21192,403:192,444:39}), `run-regression-tests.sh` (FP-gate + enforce-replay + (reason,status) tuple-assert, 444-nel status-only). Verifikalva: nginx -t + zero-proxy_pass; **9/9 dim 100% frozen-match ~20s**; unit 6/6 + stat 131/131 valtozatlan; negativ proba (/.env tiltas) 6300 vektort divergaltat majd zold. **PUSH = PARTNER** (Permission denied publickey, prod leallitva S5 ota). A KOVETKEZO: a partner dont — honeypot D (ASN/geo a tamado IP-kbol, sajat geo-reader, no libloc) / gap-loop a B6 jeloltekbol / scanners.list bovites.

---

## 1. Mission

Egy **edge-tuzfal** vanilla nginx 1.30.2-re: egy **dinamikus C modul**
(`ngx_http_waf_module.so`, ami KET modult tartalmaz: HTTP + STREAM), plusz a
beepitett `ngx_mail` proxy az SMTP oldalra, egy **kozos reputacios maggal**.
Karcsu, gyors edge-szuro: scanner/bot path-tiltas, Apache-fingerprint alcazas,
sajat beepitett nanolibloc-alapu geo/reputacio, SMTP-vedelem, lock-free
statisztika.

### Eddigi sessionok
- **S1-S2:** build-lanc + Phase 0-4 (scanner+bot, spoof, geo, SMTP auth_http, STREAM).
- **S3:** lock-free stats/status alrendszer.
- **S4:** WAF feature-bovites (JA4 + ASN block + method filter + detect mode + would_block) — commit `c1f8a72`.
- **S5 (2026-06-14):** takaritas + ket review (code-quality + security) + 2 HIGH security fix + honeypot log-elemzes (A=gap-analizis) + **uj architektura-irany felvetese: a WAF mint DETECTOR** (`$waf_attack_vector_type`). 5+2 commit.
- **S6 (2026-06-14):** **a detektor-irany ELVETVE** (lasd Decisions #41), honeypot threat-intel dokumentalva (`docs/threat-model.md`), README pontossag-audit + javitas. Commit `3a6854c`.
- **S7 (2026-06-14):** ket tech-debt lezarva (parser-dedup Minor3 + doc gap-fill nginx-prozaban, NEM Doxygen) + location.db integritas a roadmapra. Commit `a2f367b`. Build fast-target MEGEROSITVE.
- **S8 (2026-06-14):** **feature-roadmap #1 LESZALLITVA** — args/cookie/referer signature-blocklist (action-bucketed 404/403/444, %-dekodolt match, stateless). A scanner compile/lookup generalizalva (caller-owned `re_bucket`); 3 uj reason auto-extenddel; 3 uj direktiva + kozos setter; PREACCESS args->cookie->referer lanc. Commit `3a48d61`. +20 integr. teszt -> **77/77** zold, 6/6 unit, 0 warning.
- **S9 (2026-06-14):** **feature-roadmap #2 LESZALLITVA** — CIDR-alapu fake-bot verifikacio. `waf_fake_bot_block on|off` + `waf_verified_bot <class> <path>` (TAKE2); PREACCESS: claimed crawler/ai-crawler + IP a publikalt CIDR-en KIVUL -> 403, stateless (no DNS/cache). Uj `WAF_REASON_FAKE_BOT` (auto-extend) + `ngx_http_waf_verified_bot_compile` (waf_match.c, `cidr_add` parja). Commit `0638343`; +16 integr -> **93/93** zold, 6/6 unit, 0 warning. README dokumentalva (`1e490d7`). Ket verifikalo minion (impl-inspector COMPLETE 14/14 + security-officer 0 defekt).
- **S10 (2026-06-14):** **feature-roadmap #4 LESZALLITVA** — location.db **load-time alairas-ellenorzes** (ECDSA P-521 / SHA-512, pinned IPFire pubkey, fail-closed). `ngx_http_waf_geo_verify()` a `geo_open`-ben (HTTP+STREAM egyben); unsigned/tampered/truncated/oversized DB -> `nginx -t` non-zero, nginx nem indul/reload-ol. Uj `reference/locverify.c` standalone dev-oracle (libloc nelkul) bizonyitotta a kulcsot+hash-rendet MINDKET iranyban a valodi DB-vel. Commit `24f9145` (kod+teszt+README+oracle egyben). +8 negativ assert -> **101/101** integr, 6/6 unit, 0 warning. Ket verifikalo minion: impl-inspector COMPLETE 16/16 + security-officer (find->verify) 0 kihasznalhato defekt (4 finding mind SUPPRESSED).
- **S11 (2026-06-15):** **feature-roadmap #3 LESZALLITVA — A ROADMAP TELJES (mind a 4 feature kesz).** Lock-free per-IP **token-bucket rate-limit** mindharom fejen (HTTP 429 / STREAM L4 drop / MAIL `Auth-Status: rate limit`). Uj `waf_rate.c`+`.h`: fixed-size open-addressed per-IP tabla EGY `waf_rate` shm zonaban (a `cc[512]` tabla mintajara, NEM `limit_req` rbtree+mutex); FNV-1a kulcs, packed 64-bit CAS, **eviction-on-full** (sosem silent drop), **fail-open** (sosem hamis-pozitiv ban). `waf_rate_zone size=..` (http main, azonnali shm, ordering-EMERG) + `waf_rate_limit rate=Nr/s|m|h [burst=N] [for_geo=CC,..]` (HTTP loc + mail) + `waf_stream_rate_limit` (stream srv). Uj `WAF_REASON_RATE_LIMIT` + `http_resp_429` + `rate_overflow` mind a 3 stat-formatumban. Token-allapot reloadkor megorzodik; IPv6 /64-re kulcsolva. Commit `c426d98` (kod+teszt+README egyben). +27 uj eset -> **128/128** integr, 6/6 unit, 0 warning. Ket verifikalo minion: impl-inspector COMPLETE **22/22** + security-officer (find->verify) **0 kihasznalhato defekt** (11 finding mind SUPPRESSED). waf-feature-roadmap memoria frissitve (mind a 3 megtartott feature SHIPPED).
- **S12 (2026-06-15):** `sa`-trust audit LEZARVA (dok-verifikacio, nincs kodvaltozas; Decisions #65).
- **S13 (2026-06-15):** **honeypot program START.** Step 0 (replay-vektor extraktor `extract-replay-vectors.pl` -> `replay-vectors.jsonl`, mind a 9 §3 osztaly ±5%-on belul) KESZ; header-attack threat-intel doksi (`docs/threat-intel-sources.md`, deep-research sweep) KESZ; **B terv (`docs/honeypot-B-plan.md`) kesz + plan-inspector (APPROVE-WITH-CHANGES) + security-officer (REVISE) findingek mind beepitve.** Nincs WAF .c valtozas.
- **S14 (2026-06-15):** (1) **uj WAF feature `waf_reason_header`** (X-WAF-Reason header, default OFF, prod-biztos; ELSO WAF .c valtozas `c426d98` ota; build 0 warning, 131/131 integr). (2) **honeypot B work-stream KESZ** — extractor `--ua-vectors`/`--referer-vectors`, `build-header-fixtures.pl` + 7 kulso fixture sanitizalva, `waf-replay-test.conf` (7 dimenzio-tiszta detect vhost), `replay-client.pl` raw-socket kliens + `run-replay-tests.sh` harness; teljes sweep ~208k keres; **FP-gate PASS**, coverage-meter + 49,155 uncovered (top-2000 export) + gap-loop jeloltek. Partner ELFOGADTA. NINCS commit meg (HEAD `c426d98`).
- **S15 (2026-06-15):** **COMMIT** — ket logikai commit a main-en (`dbee0ce` waf_reason_header + `291621d` honeypot B tooling); `.gitignore` atallitva (feed-ek + `fixtures/` fel, results/riport ignore; Decision #77). Munkafa tiszta, HEAD origin/main elott 8.
- **S16 (2026-06-15):** **honeypot C LESZALLITVA + BEKOMMITOLVA (`2f0c18e`)** — enforce-modu, bekommitolt regresszios fixture + harness (5 artifact, egy logikai commit). `replay-client.pl --enforce`; dedikalt 283xx conf; ketpasszos freeze-generator; 21,263 path/args + 160 header frozen vektor; FP-gate + tuple-assert harness. **9/9 dim 100% frozen-match**, unit 6/6 + stat 131/131 valtozatlan, negativ proba bizonyitja a regresszio-erzekenyseget. NINCS push (partner).
- **S18 (2026-06-15):** **gap-loop iteracio 2 (config/IaC + appliance fingerprints) LESZALLITVA + BEKOMMITOLVA (`cf244cb`, UJ commit).** A partner a 3 karbantartasi iranyt valasztotta (stale-fix + tovabbi gap-loop + scanners.list bovites); honeypot D kihagyva. Stale-fix = NO-OP (a §6.B mar S17-ben done). scanners.list: config/IaC broad-ext (`\.ya?ml$`/`\.properties$`/`\.tfstate`/`\.tfvars$`) + ~30 enumeralt .json/dotfile secret + Symfony `/debug/default/view` + generikus .php kiterjesztve (.phpN + `.php::$DATA`/`.php~`/`.php.old`) + bare `/phpinfo` + 16 appliance/VPN/RCE fingerprint. Generikus szotar-tail KIHAGYVA (partner). B FP-gate PASS (uncatalogued 21.6->35.3%, appliance 100%, php 99.9%); C re-freeze 38,905->40,614 ({404:40,573 403:146 444:55}, 403/444 byte-azonos); 9/9; unit 6/6 + stat 131/131 valtozatlan; NINCS .c valtozas. Egy p:minion-runner vegezte a compile+B+freeze+C+unit+stat futtatast.
- **S17 (2026-06-15):** **gap-loop (honeypot §6 A) + §3.1 + misc secret-leaks LESZALLITVA + BEKOMMITOLVA (`a1bda45`, amend).** scanners.list: generikus .php catch-all (php->99.2%, phpadmin->98.5%), wlwmanifest (wp->99.5%), /bin/sh, /remote/login, /+cscoe+/, Trinity, /hello.world, + credential/config/infra-leak cluster (uncatalogued 14.1->21.6%); args.list php://input 444. Akcio-flip: ~46 phpmyadmin/pma *.php 403->404 (scanner_lookup 404>403>444 precedencia). B FP-gate PASS; C fixture re-frozen 21,263->38,905; 9/9 frozen-match; unit 6/6 + stat 131/131 valtozatlan; NINCS .c valtozas (listak hot-reload).

### Why this matters
- Kivaltja a regi `nginx-firewall.conf`-ot. HTTP/3 (QUIC) kell -> bundled OpenSSL 3.5.7.
- A stats hot path lock-free; a dimenziok korlatosak (zart orszag-halmaz, config-ido vhost-tomb) — soha per-IP.
- **(S4) JA4 = observability-only, SOHA nem blokkol.** A detect mode azert kell, hogy egy policy-t meg lehessen merni eles blokkolas elott.
- **(S4) Fail-closed invarians (CWE-636):** egy `waf` direktiva nelkuli config ENFORCE-ol (eddig off volt).
- **(S6) A WAF blokkolo marad, NEM detektor.** A scanners.list tovabbra is akcio-alapu (404/403/444) block. A detektor-absztrakcio (osztalyozas + nginx map/if routing) egy nem letezo problemara adott megoldas volt — lasd Decisions #41.
- **(S10) A geo DB MOST kriptografiailag verifikalt betolteskor.** A strukturalis bounds-check (S5 geo-OOB fix) onmagaban nem vedett egy strukturaltan-valid de MITM-elt/csonkolt DB ellen; a libloc beepitett ECDSA-alairasat most ellenorizzuk (libloc LINKELESE NELKUL — no-libloc invarians).
- **(S11) A roadmap utolso feature-e (rate-limit) az EGYETLEN ami minimalisan megtori a stateless-seget** (a per-IP szamlalo elkerulhetetlen). A megoldas egy lock-free per-IP tabla EGY shm zonaban, KULCS-egyenloseg (nem hash) kapuzza a state-mutaciot; minden hibaut **fail-open** (sosem hamis ban). A zona kulcs CSAK a kliens IP (nem location/rule) -> EGY bucket IP-nkent, megosztva L4+L7 kozott (szandekos egyesitett per-IP budget). A token-bucket a throttle (nincs kulon `ban=dur`); HTTP 429 Retry-After NELKUL (partner-dontes).

### Scope
- **In scope:** HTTP WAF modul, ngx_mail auth_http, STREAM (L4) fej, kozos reputacios mag, HTTP/2+3 build, lock-free stats; JA4 fingerprint, ASN-block, HTTP method-filter, detect mode, would_block counterek; **adatvezerelt scanners.list karbantartas a honeypot-korpuszbol** (akcio-alapu block); **(S10) geo DB load-time alairas-verifikacio**; **(S11) lock-free per-IP token-bucket rate-limit (roadmap #3, KESZ).**
- **Out of scope:** Hyperscan, maxmind, request-body inspekcio, dinamikus auto-ban, per-IP/top-N kovetes (a rate-limit per-IP tablaja az EGYETLEN per-IP state, korlatos meretu), ngx_mail forras patchelese; **(S11) tobb kulon rate-zona (EGY zona), explicit `ban=dur`, Retry-After header, ASN/flag-alapu rate-rule (csak `for_geo` CC), konfiguralhato IPv6-prefix (fix /64) — mind MVP-n kivul.** **NEM hasznalunk liblocot / a `location` CLI-t** (partner kategorikus; Decisions #25) — a verify is SAJAT OpenSSL-kod, nem libloc. **(S6) `$waf_attack_vector_type` detektor-feature ELVETVE.** **(S6) protokoll-junk (binary/L4 a HTTP porton) HTTP-szintu kezelese ELVETVE** — az nginx parser mar 400-ozza, WAF-hatokoron kivul. **(S10) location.db verify = LOAD-TIME ONLY, nem per-request** (partner: "load-time verify eleg").

---

## 2. Current state

**HEAD = `cf244cb` (origin/main = `2f0c18e` elott 2 commit-tal: `a1bda45` S17 + `cf244cb` S18; egyik SINCS push-olva).**
**S18: GAP-LOOP ITERACIO 2 (config/IaC + appliance fingerprints) LESZALLITVA +
BEKOMMITOLVA** (`cf244cb`, UJ commit, NEM amend) — a munkafa TISZTA. scanners.list
adatvezerelt bovites (honeypot §6 A masodik iteracio): config/IaC/secret-leak
BROAD-EXT (`\.ya?ml$`/`\.properties$`/`\.tfstate`/`\.tfvars$`) + ~30 enumeralt
.json/dotfile secret-store + Symfony `/debug/default/view` + generikus .php
kiterjesztve (.phpN + source-leak suffixek) + bare `/phpinfo` + 16 appliance/VPN/
RCE fingerprint. Generikus szotar-tail KIHAGYVA (partner). B FP-gate PASS; C
fixture re-frozen 38,905->40,614 ({404:40,573 403:146 444:55}); 9/9 frozen-match;
NINCS .c valtozas. A feature-roadmap (1-4) TELJES; a honeypot-program **A/B/C
KESZ, D hatravan** (a gap-loop ket iteracioja lefutott; tovabbi iteraciok
lehetsegesek, de a fo jeloltek MAR BENT).

**Working tree (S16 vege, `git status`): TISZTA** — minden C-valtozas
commitolva. Csak az ignore-olt scratch marad a lemezen: `corpus/.freeze-tmp/`
(detect/enforce probe-kimenetek, covered-subset feed-ek, compare.pl), valamint a
B per-run results/riportok, `.cache/`, `ngxlogs/` (mind reprodukalhato /
partner-kezelt).
- **NINCS push** (push = PARTNER hataskore; Permission denied publickey).

### Completed
- [x] **(S1-S4)** teljes build-lanc + osszes feature commitolva `c1f8a72`-ig.
- [x] **(S5)** `1f03413` scanners.list->lists/; `a14a0c8` 2 HIGH geo-OOB + F4 auth_http trusted-peer + F8 Host-escape; `e3b9720` Minor1 flag_cc; `ea9d65f` cc_map dead-code + magic96; `d2b557a` adatvezerelt scanners.list bovites. 6/6 unit + 57/57 integr. zold.
- [x] **(S5/S6 kozott, NEM-checkpointolt build-commitok):** `2086451` PCRE2 10.47 in-tree build; `e13e2df` CMake `;`-split fix.
- [x] **(S6) `3a6854c`** — `docs/threat-model.md` + README pontossag-audit 11 javitassal.
- [x] **(S6) detektor-vizsgalat es ELVETES** (Decisions #41-42).
- [x] **(S7) `a2f367b`** — parser-dedup (`ngx_http_waf_next_line()`) + 27 nginx-proza doc-komment. Build fast-target MEGEROSITVE; 6/6 + 57/57 zold.
- [x] **(S8) `3a48d61`** — **feature #1: args/cookie/referer signature-blocklist.** 8 forras + 3 uj lista + 2 fixture. **77/77** + 6/6 + 0 warning.
- [x] **(S9) `0638343`** — **feature #2: CIDR fake-bot verify.** waf_rep.h `WAF_REASON_FAKE_BOT`; ngx_http_waf.h mezok; waf_match.c `verified_bot_compile`; module.c 2 direktiva + PREACCESS. **93/93** + 6/6 + 0 warning.
- [x] **(S9) `1e490d7`** — README: 2 direktiva-sor + "Verified-bot" szekcio + `$waf_reason` token-lista pótlas.
- [x] **(S9) ket verifikalo minion:** impl-inspector COMPLETE 14/14 + security-officer (code-mode) 0 defekt.
- [x] **(S10) `24f9145`** — **feature #4: location.db load-time alairas-verify.** `waf_geo.c`: OpenSSL includes (evp/pem/bio/err), header-layout `#define`-ok (HDR_SIZE 4192, DATA_OFF 4200, SIG_MAX 2048, ZERO 60..4160, sig offsetek 68/70/72/2120), pinned PEM `static const char[]`, `ngx_http_waf_geo_verify()` (dual-sig ECDSA P-521/SHA-512, NULL digest, accept CSAK `==1`, present-slot 1..2048, egy elo snapshot, single goto-cleanup, ERR_clear_error entry-n), szigoru pre-mmap size guard (min 4200 + max 512 MiB), verify-hivas a magic check UTAN a blokk-loop ELOTT. `reference/locverify.c` UJ dev-oracle (NEM buildelt). run-stat-tests.sh +8 negativ assert (tampered/header-only/tiny/cap-sanity). README "Signature verification" szekcio + `reference/` sor. **101/101** integr (93+8) + 6/6 unit + config-test OK + 0 warning. `config` ES `waf_geo.h` VALTOZATLAN (libcrypto mar linkelve a JA4 miatt).
- [x] **(S10) ket verifikalo minion (read-only):** **impl-inspector** = COMPLETE **16/16** (oracle<->modul konstans-egyezes igazolt); **security-officer find->verify** = 0 kihasznalhato defekt, mind a 4 finding **SUPPRESSED** (F1 error-queue + F3 oracle FIXED a sessionban, F2 pinned-pubkey by-design/nem-titok, F4 cap nem-DoS). Az accept/reject ut defekt-mentes.
- [x] **(S11) `c426d98`** — **feature #3: lock-free per-IP token-bucket rate-limit (HTTP+STREAM+MAIL).** Uj `waf_rate.c`+`.h` (mag: FNV kulcs, token-bucket CAS eviction-on-full-lal, zona-init, rule_select, rule_add, overflow-getter); `waf_rep.h` `WAF_REASON_RATE_LIMIT`; `ngx_http_waf.h` `loc_conf.rate_rules`; `waf_status.h` `main_conf.rate_zone` + `stat_shm_t.http_resp_429`; `ngx_http_waf_module.c` 2 direktiva+setter + PREACCESS integracio + 429-case + merge; `waf_status.c` http_resp_429+rate_overflow render (3 formatum) + FIXED_LINES 96->112; `waf_stream.c` rate-integracio + zona-resolve; `waf_authhttp.c` verdict+rate+deny; `config` waf_rate.c/.h; tesztek + README. **Build reconfigure-rel** (uj .c) 0 warning. **128/128** integr + 6/6 unit.
- [x] **(S11) ket verifikalo minion (read-only):** **impl-inspector** = COMPLETE **22/22** (0 logikai bug; egyetlen LOW elteres a `>=` eviction tie-break, biztonsagosnak itelve); **security-officer find->verify** = **0 kihasznalhato defekt**, mind a 11 finding **SUPPRESSED** (mind fail-open / platform-biztos / helyesen guardolt / dokumentalt dizajn; integer-overflow bizonyitottan nem fordul elo).
- [x] **(S13) honeypot step 0** — `modules/ngx_http_waf/tests/corpus/extract-replay-vectors.pl` (durable perl one-pass extraktor, label-first) -> `replay-vectors.jsonl` (84,970 unique vektor) + `.summary.txt`; mind a 9 §3 osztaly ±5%-on belul (label-first baseline-javitas + measurement-kalibralt regexek). Derivatumok gitignore-olt; a .pl committable (NEM commitolva meg).
- [x] **(S13) header-attack threat-intel** — `docs/threat-intel-sources.md` (deep-research: SecLists/CRS/Nuclei/bad-bot-blocker/PortSwigger; 25 claim verified 3-0).
- [x] **(S13) B work-stream TERV** — `docs/honeypot-B-plan.md`, ket inspector-minionnal ellenorizve (plan-inspector APPROVE-WITH-CHANGES + security-officer REVISE), minden finding beepitve. CSAK terv; implementacio a kovetkezo session.
- [x] **(S14) `waf_reason_header` direktiva** — kapcsolhato `X-WAF-Reason` valasz-header, default OFF (prod-biztos), `on` a teszt-configokban. `loc_conf.reason_header` flag + output header-filter a module.c-ben (`ngx_http_waf_reason_header_filter`, sajat `next` ptr, postconf-ban regisztralva, `r==r->main` gate). Build 0 warning (fast-target, NEM reconfigure). Smoke: minden dimenzio helyes verdiktet ad (scanner_path/scanner_ua/empty_ua/cookie/fake_bot/none). Default-OFF bizonyitva (waf-stat-test.conf direktiva nelkul -> nincs header). **131/131** integr (+3 reason-header assert), README direktiva-sor. NINCS commitolva.
- [x] **(S14) honeypot B work-stream (mind a 6 lepes)** — (B1) extractor `--ua-vectors`/`--referer-vectors`; (B2) `build-header-fixtures.pl` + 7 kulso fixture (CRS/SecLists/bad-referrers/crawler-json/FuzzDB) sanitizalva -> ua/referer/cookie/fakebot JSONL fixture-ok provenance-szel; (B3) `waf-replay-test.conf` 7 dimenzio-tiszta detect vhost (config-teszt OK); (B4) `replay-client.pl` raw-socket kliens (S1/S2/S3 invariansok review-zva) + `run-replay-tests.sh` harness; (B5) teljes sweep ~208k keres; (B6) gap-loop jeloltek. **FP-gate PASS**, X-WAF-Reason per-vektor technika PONTOSAN validal a would_block counter ellen (path covered=delta=35397). Partner ELFOGADTA.

- [x] **(S15) `dbee0ce` + `291621d`** — **COMMIT.** (a) `waf_reason_header` feature (5 fajl, 77 ins; HUP-reload-safe, stat shm sizeof valtozatlan). (b) honeypot B tooling + S13 maradek (26 fajl, 166,858 ins: replay harness + extractor + fixture-builder + korpusz-feed-ek + kulso fixtures + docs + .gitignore + scanners.list). `.gitignore` atallitva (Decision #77: feed-ek + `fixtures/` fel; results/riport/uncovered/`.cache/`/`ngxlogs/` ignore). README ket hunkja `git apply --cached`-csel szetvalasztva a ket commitba. Commit-guard: semmi derivatum-result nem szivargott be. Munkafa tiszta, HEAD origin/main elott 8. Push = PARTNER.
- [x] **(S16) `2f0c18e`** — **honeypot C: enforce-modu, bekommitolt regresszios fixture + harness.** 8 fajl, egy logikai commit: (a) `replay-client.pl` `--enforce` mod (friss Connection:close socket/keres + first-byte 444-probe + sentinel->444 int; detect byte-azonos); (b) `waf-regression-test.conf` UJ (283xx, 13 vhost: reg-status 28300 + detect/enforce par dimenziónkent 28301-28312, vhostonkent EGY matcher, `waf_reason_header on` GLOBALISAN, zero proxy_pass / trusted_proxy / rate / geo); (c) `freeze-regression-fixture.pl` UJ (ketpasszos: detect->reason, enforce->status; dedup uri/value; covered-subset enforce-pass; list-form system, fix `.freeze-tmp/` temp); (d) `regression-vectors.jsonl` (21,263 path/args) + (e) `regression-headers.jsonl` (160 ua/referer/cookie/fakebot) frozen verdikt {expected_reason,expected_status}; (f) `run-regression-tests.sh` UJ (nginx -t + zero-proxy_pass assert, FP-gate, enforce-replay, perl join+compare, divergencia-print, 444 status-only); (g) `.gitignore` (`.freeze-tmp/` ignore); (h) `docs/threat-model.md` §6.C (planned)->(DONE) + intro. **9/9 dim 100% frozen-match ~20s**; FP-gate PASS; unit 6/6 + stat 131/131 valtozatlan; negativ proba (/.env tiltas) 6300 path-vektort divergaltat (`got=(none,404)`), visszaallitva zold. Push = PARTNER (HEAD origin/main elott 9).
- [x] **(S17) `a1bda45`** (amend) — gap-loop iteracio 1: generikus .php catch-all + wlwmanifest + 6 path-minta + credential/config/infra-leak cluster + php://input args. Fixture 21,263->38,905. 9/9 + 6/6 + 131/131.
- [x] **(S18) `cf244cb`** — **gap-loop iteracio 2: config/IaC broad-ext + ~30 enumeralt secret + Symfony + .php-broaden + 16 appliance fingerprint.** 3 fajl (scanners.list +61/-4, regression-vectors.jsonl +1709, threat-model.md). Fixture 38,905->40,614 ({404:40,573 403:146 444:55}, 403/444 byte-azonos). B FP-gate PASS (uncatalogued 21.6->35.3%, appliance 100%). 9/9 + 6/6 + 131/131. NINCS .c valtozas. Generikus szotar-tail KIHAGYVA. NEM push (partner).

### In progress
- _(none)_

### Not started (a valos hatralek)
- **A feature-roadmap (1-4) TELJES** — nincs tobb tervezett roadmap-feature. A deployolando kod (HEAD `c426d98`) a #1+#2+#3+#4 feature-t MIND tartalmazza.
- _(Eles prod restart + `git push`: a PARTNER hataskore — S12-ben SZANDEKOSAN kivettuk a checkpoint hatralekabol/teendoibol; ne vedd fel ujra. A prod le van allitva S5 ota; a HEAD origin/main elott 6 commit-tal van.)_
- ~~**Honeypot B IMPLEMENTACIO**~~ → **(S14) KESZ** (mind a 6 lepes, partner elfogadta; lasd Completed/Timeline S14). A B kimenete (uncovered-export + coverage) a **C** (bounded top-N/class fixture CI-ba) es a gap-loop bemenete; utana **D** (ASN/geo a tamado IP-kbol, sajat geo-reader, no libloc).
- ~~**A KOVETKEZO MUNKA: COMMIT**~~ → **(S15) KESZ** (`dbee0ce` + `291621d`).
- ~~**Honeypot C** (bounded fixture)~~ → **(S16) KESZ** (`2f0c18e`) — a partner a "mind" (teljes covered halmaz, NEM top-N) mellett dontott; enforce-modu regresszios fixture + harness leszallitva es bekommitolva. **A KOVETKEZO (uj context): honeypot D** (ASN/geo a tamado IP-kbol, sajat geo-reader, no libloc; `reference/loctest.c` geo-OOB bugot hordoz -> fixelni) VAGY a **gap-loop** a B6 jeloltekbol (dynamic-ext `\.php` 127k / wlwmanifest 13k / cgi-bin->/bin/sh 4.3k / php://input 2.1k / Symfony / VPN; generikus `\.php` CSAK detect-FP-check utan) VAGY scanners.list adatvezerelt bovites — **partner dont, NE kezdj bele iranymutatas nelkul.**
- ~~**(opcionalis) sajat `sa`-feloldas (XFF / real-IP trust-hatar) kulon audit**~~ → **(S12) LEZARVA.** Kivizsgalva (minion-explorer teljes adatfolyam-terkep mind a 3 fejen). A trust-modell MAR teljesen dokumentalt a README-ben: HTTP XFF trust (`README.md:354-360`, `:490-492`, `:810-811`), MAIL loopback Client-IP gate + `waf off` invariáns + fail-open (`:498-521`), STREAM verbatim peer (`:538-540`), rate-limit ugyanazt a canonical IP-t kulcsolja (`:643-645`). NINCS doc-gap. Konszolidalt trust-tabla a partnernek INLINE atadva (chat), SZANDEKOSAN NEM doksiba (partner dontes). Lasd Decisions #65.

### Blocked
- _(none)_

---

## 3. Decisions log

_(1-24: S1-S3. 25-33: S4. 34-40: S5. 41-47: S6-S7. 48-54: S8-S9. Megorizve.)_
1-24. **(S1-S3)** OpenSSL 3.5.7 bundle, `--build=E`, nginx-konvenciok, scanner-bucketek, Apache-token, geo mmap, nanolibloc, docker TILTOTT, Phase-4 IP-only, SMTP ket-ag, fail-open Client-IP, STREAM opaque-pointer, shm limit_req minta, teszt-portok 28xxx/29xxx.
25-33. **(S4)** no-libloc; `waf` 3-allapotu enum fail-closed `enforce`; JA4 getter ex_data-bol; JA4 ALPN hex-fallback; SHA256=EVP_Digest; ctest.h vendorolva; method-teszt DELETE; task-017 cron DESCOPE; commit a main-re.
34-37. **(S5)** geo OOB fix (size_t offset + full-node guard); F4 auth_http trusted-peer gate; F8 spoof Host escape; Minor1 flag_cc whitelist modban is tilt.
38-40. ~~**(S5)** detektor-irany (classify + $waf_attack_vector_type + vektor-cimkek).~~ → **superseded by #41 (S6).**
41. **(S6)** **$waf_attack_vector_type DETEKTOR ELVETVE** — empirikusan a vektor 99.97% parser-400, a path-probe-okat a scanners.list mar blokkolja. - *Source:* user.
42. **(S6)** Protokoll-junk HTTP-szintu kezelese ELVETVE (parser 400-oz a PREACCESS elott). - *Source:* user.
43. **(S6)** Uj doksi `docs/threat-model.md` (honeypot threat-intel + B/C/D terv). - *Source:* user.
44. **(S6)** README = pontossag elsobbsege, NEM agressziv karcsitas. - *Source:* user.
45. **(S7)** location.db integritas-ellenorzes FELKERULT a roadmapra (infra/supply-chain). - *Source:* user.
46. **(S7)** "blanket Doxygen" tech-debt = nginx-proza GAP-FILL, NEM Doxygen. - *Source:* user.
47. **(S7)** parser-dedup (Minor3) KESZ (`ngx_http_waf_next_line()`). - *Source:* user.
48. **(S8)** feature #1 = action-bucketed (404/403/444), %-dekodolt match, reason PER-SUBJECT. - *Source:* user.
49. **(S8)** `scanner_compile` `wlcf` parametere ELHAGYVA (unused lett a generalizalas utan). - *Source:* agent.
50. **(S8)** fixture-listak a `lists/`-be (prod-hasznalhato), statikus fixture a `sandbox/html/`-be. - *Source:* agent.
51. **(S9)** feature #2 = CIDR fake-bot verify, NEM DNS; loader a waf_match.c-ben (`read_file`/`next_line` static). - *Source:* user + plan-inspector.
52. **(S9)** a teszt a CONNECTION PEER-re kulcsol (nincs `waf_trusted_proxy`); ezert ket fixture-lista. - *Source:* agent.
53. **(S9)** lazy-alloc invarians: ures fajl => NULL slot => class skip (sosem block-all). - *Source:* security-officer.
54. **(S9)** `waf_allowlist` NEM mentesit a fake-bot alol (ortogonalis ellenorzesek). - *Source:* security-officer N1 -> README.
55. **2026-06-14 (S10)** — **feature #4 = LOAD-TIME verify ONLY, nem per-request.** A `geo_open` (config-parse) az egyetlen chokepoint; HTTP+STREAM mindketto ezt hivja. Tiszta config-ido koltseg (egy SHA-512 pass DB-nkent), nulla request-path hatas. - *Source:* user ("load-time verify eleg").
56. **2026-06-14 (S10)** — **pinned pubkey COMPILE-IN, no directive, no opt-out, fail-closed.** A pinned IPFire P-521 kulcs `static const char[]` PEM a waf_geo.c-ben; unsigned DB (mindket sig-hossz 0) ELUTASITVA; barmilyen OpenSSL hiba ELUTASITVA. Kulcs-rotacio (tobb-eves horizont) = modul-rebuild. - *Source:* user (locked decisions a tervben).
57. **2026-06-14 (S10)** — **Step-0 kulcs-acquisition gate KOTELEZO az integracio ELOTT.** A kulcsot ket fuggetlen HTTPS forrasbol (git.ipfire.org + sources.debian.org) byte-azonosan szereztem (NEM LLM-relayed base64). A valodi DB az ORAKULUM: a `reference/locverify.c` (standalone, libloc nelkul, NEM buildelt) bizonyitotta MINDKET iranyt (VALID a jo DB-n, INVALID egy data-byte flipre, reject csonkoltra). Csak gate-PASS utan agyaztam be a kulcsot. - *Source:* user (terv Step 0) + agent.
58. **2026-06-14 (S10)** — **EGY koordinatarendszer (off-by-8 ellen):** minden live-DB olvasas file-abszolut `base+N`; a stack header-MASOLAT copy-local 0..4192, ahol `copy-local N == base + 8 + N`; a zero-regio copy-local [60,4160). Komment rogziti, hogy a ket buffer (mmap base vs stack copy) sose keveredjen. - *Source:* terv N1' + agent.
59. **2026-06-14 (S10)** — **max-size cap a MERT valodi DB-hez kotve:** valodi `location.db` = 63,517,012 byte (2026-06-12); cap = 512 MiB (~8.5x headroom), dokumentalva kommentben + commitban; a Step-0 oracle + Step-2 teszt assertali hogy a valodi DB jovel a cap alatt (no self-inflicted fail-closed DoS). A size guard PRE-mmap marad (min 4200, max 512 MiB; `size` unsigned -> sorrend szamit). - *Source:* terv N2/M3 + mert ertek.
60. **2026-06-14 (S10)** — **F1 + F3 finding-fix a security-find UTAN, ujra-verifikalva.** F1: `ERR_clear_error()` a verify entry-n (a drainelt hiba garantaltan EBBOL a verifybol valo). F3: a dev-oracle `ERR_error_string_n` (thread-safe, bufferes) az `ERR_error_string` helyett. F2 (pinned pubkey forrasban) es F4 (512 MiB cap) by-design, nincs teendo. - *Source:* security-officer find -> agent fix -> verify SUPPRESSED.
61. **2026-06-15 (S11)** — **rate-limit = token bucket** (smooth/leaky), NEM sliding window; **HTTP 429 Retry-After NELKUL**; **`for_geo` mar az MVP-ben** (reputacio-tudatos felulbiralas); **mindharom fej egy menetben** (HTTP PREACCESS / STREAM L4 / MAIL auth_http); **eviction-on-full** (tele tablanal a legregebben frissitett slotot vesszuk at, NEM silent drop). - *Source:* user (e session dontesei).
62. **2026-06-15 (S11)** — **EGY `waf_rate` zona, KULCS = kliens IP ONLY** (nem location/rule) -> egy bucket IP-nkent, megosztva minden location + L4 + mail kozott (szandekos egyesitett per-IP budget). A rule csak a rate/burst/period parametert adja az adott check-hez. **HTTP-only zona-create** (`waf_rate_zone` http main, azonnali shm mint a `limit_req_zone`), STREAM/MAIL size-0 resolve; ez kiiktatja a zona-ordering EMERG-et (H3). `waf_rate_limit` zona NELKUL -> EMERG. - *Source:* user + plan (H3) + agent.
63. **2026-06-15 (S11)** — **Fixed-point SCALE=1000**, NE ms-ratat tarolj (1r/m egeszben 0-ra csordulna); refill osztas UTOLJARA; rate_num_fp es burst_fp egyarant <= UINT32_MAX (a 64-bit szorzat bizonyithatoan nem csordul). **IPv6 /64-prefixre kulcsolva** (per-/128 trivian megkerulheto; intra-/64 collateral szandekos anti-evasion default, README-ben dokumentalva). - *Source:* plan (H1/H5/P3/P6) + agent.
64. **2026-06-15 (S11)** — **fail-open MINDEN hibauton** (NULL zona / ismeretlen csalad / CAS-eheztetes / vesztes evict-CAS) — az EGYETLEN valodi defekt-osztaly itt a HAMIS-POZITIV ban; a fail-open (extra token, kihagyott eviction) elfogadott dizajn, NEM eszkalalando. A `>=` eviction tie-break szandekos (garantalja hogy `oldest` nem-NULL ha volt foglalt slot). - *Source:* plan + security-officer verify + impl-inspector V1.
65. **2026-06-15 (S12)** — **a #3 `sa`-feloldas audit = DOKUMENTACIO-VERIFIKACIO, nem kodmunka; LEZARVA.** A minion-explorer feltarta mind a 3 fej trust-hatarat (HTTP: POST_READ `:436` trust-dontes -> `ctx->client_sa`; STREAM: `:214` verbatim peer; MAIL: `:64` loopback `peer_trusted()` -> Client-IP). Megallapitas: a teljes trust-modell MAR dokumentalt a README-ben, nincs hianyzo teny. A partner kerte a konszolidalt trust-tablat, de **SZANDEKOSAN CSAK inline** (chat) kapta meg — a doksiba iras redundans lett volna, ezert NEM tortent. Nincs kodvaltozas. - *Source:* user ("eleg dokumentalni ha nincs dokumentalva" -> "de csak ide nekem, ne doksiba").
66. **2026-06-15 (S13)** — **step 0 "valid attack vector" def:** minden szintaktikailag valid HTTP keres aminek DEKODOLT path-ja NEM legit baseline (`^/$`, `^/app\.`, static-ext, favicon/robots/sitemap); a §4 parser-junk (request != `METHOD SP URI SP HTTP/x.y`) es a `10.0.0.0/24` health-check KIZARVA. - *Source:* user.
67. **2026-06-15 (S13)** — **extractor: decode a baseline+labelinghez, DE LABEL-FIRST** — baseline csak akkor zar ki, ha NINCS attack-class. Ez a sanity-gate javitas: megakadalyozza hogy a static-ext baseline elnyelje a hostile `/owa/auth/x.js`, `/.env;.jpg`-t. - *Source:* agent (sanity-gate finding).
68. **2026-06-15 (S13)** — **.gitignore: csak a derivatumok** (`replay-vectors.jsonl`/`.summary.txt`), NEM a teljes `corpus/` — kulonben a .pl es a C-fixture sem lenne committable. (Terv-eltérés a literal "corpus/ gitignore"-tol, indokolt.) - *Source:* agent.
69. **2026-06-15 (S13)** — **static-ext-cloaked probek** (Cisco `/+cscoe+/`, `env.js`, `server.js` stb.): KOMMENTELT `scanners.list` szekcio ("kettő között" megoldas) — dokumentalt jovobeli jelolt, NEM aktiv (`#`-sorok, a WAF nem tolti be, az extraktort sem erinti); aktivalas csak detect-FP-check (B) utan. - *Source:* user.
71. **2026-06-15 (S14)** — **`waf_reason_header` = first-class WAF direktiva, default OFF.** A partner kerte hogy az X-WAF-Reason header legyen kapcsolhato es CSAK teszt kozben on. Megoldas: sajat output header-filter a module.c-ben (`loc_conf.reason_header` flag), NEM nginx `add_header $waf_reason` (azt prodban bennfelejtenek -> verdict-leak/evasion-segites). Default OFF (prod sosem fedi fel melyik szabaly fogott), merge default 0. - *Source:* user.
72. **2026-06-15 (S14)** — **B DETECT modban marad + X-WAF-Reason per-vektor attribucio** (NEM enforce). A terv detect-modot ir elo, de a §6.3 uncovered-export per-vektor adatot igenyel, amit a detect aggregat-counter nem ad. Megerositve (module.c:636 + reason getter): detect modban `ctx->reason` a would-block okra all be -> a header rendereli. Igy per-vektor lathatosag a tervhez 100%-ban huen. PONTOSAN validal (path covered==would_block delta==35397). - *Source:* agent.
73. **2026-06-15 (S14)** — **a fo `replay-vectors.jsonl` marad `--collapse-ua` (84,970):** a (method,uri) halmaz identikus a raw-zal, kisebb derivatum, a path-replayhez eleg; a nyers UA-igenyt teljesen lefedi a `replay-ua-vectors.jsonl`. - *Source:* agent.
74. **2026-06-15 (S14)** — **header fixture = JSONL `{value,count,src}`** (provenance + volumen-suly); a fakebot-tokeneket a fixture-builder a ELO `crawler.list`/`ai-crawler.list`-bol olvassa (szinkronban marad a WAF-osztalyozassal); `waf_verified_bot` osztaly = `crawler`/`ai_crawler` (ALULVONAS, nem kotojel!). - *Source:* agent.
75. **2026-06-15 (S14)** — **B kimenet-fegyelem:** az FP-gate az EGYETLEN hard assert (baseline 0 would_block); a coverage csak jelentve (trend, nem pass/fail); az uncovered-export top-2000 volumen szerint capelve; minden B-derivatum IP-mentes (a `key` mezoben elofordulo IP = tamado-szallitotta header-tartalom, NEM remote_addr). - *Source:* plan + agent.
76. **2026-06-15 (S14)** — **COMMIT-POLICY VALTOZAS (partner):** a korpusz-derivatum FEED-ek (`replay-vectors.jsonl`, `replay-ua-vectors.jsonl`, `replay-referer-vectors.jsonl`, `.summary.txt`) MOST FELMEHETNEK a repoba; a results (`replay-*-results.jsonl`) es a riportok (`replay-fp-report.txt`, `replay-coverage-report.txt`, `replay-uncovered.jsonl`) GITIGNORE-OLTAK MARADNAK. A kulso-pull `fixtures/` bekommitolasa NYITOTT (licensing: CRS Apache-2.0, SecLists MIT, FuzzDB stb. — a kovetkezo context tisztazza). - *Source:* user.
70. **2026-06-15 (S13)** — **B = COVERAGE meter, NEM pass/fail:** a §3 taxonomia-osztalyok != `scanners.list` lefedettseg (pl. `php`-nek nincs altalanos `\.php` szabaly); az uncovered-hostile export a §6/A gap-loop bemenete. Inspector-megerositett gotchak: scanner_path action-split ENFORCE-ONLY; counterek NEM reset reloadon (delta-snapshot); raw-socket perl kliens (loopback-only, absolute-form skip+count, CRLF framing-invarians); dimenzio-izolalt detect vhostok (bot_block off non-UA dim). - *Source:* agent + plan-inspector + security-officer.
77. **2026-06-15 (S15)** — **COMMIT-POLICY VEGLEGES (partner): a kulso `fixtures/` IS FELMEGY.** A #76 nyitott licensing-kerdese eldolt: minden korpusz-derivatum mehet a repoba — a sajat feed-ek (`replay-*-vectors.jsonl`+summary) ES a kulso-pull `fixtures/` (raw + jsonl) egyarant. A kulso forrasok mind permisszivek (CRS Apache-2.0 / SecLists MIT / FuzzDB / nginx-ultimate-bad-bot-blocker / monperrus crawler-user-agents), attribucio a `docs/threat-intel-sources.md`-ben. Ignore-olt marad: `replay-*-results.jsonl`, a 3 riport, `replay-uncovered.jsonl`, `.cache/`, `ngxlogs/`. Bekommitolva `291621d`-ben; commit-guard igazolta hogy semmi result/riport nem szivargott be. - *Source:* user.
78. **2026-06-15 (S16)** — **enforce-mod = Connection: close per request (H1) + first-byte 444-probe (H2) + sentinel->444 INTEGER (M1).** Friss socket vektoronkent -> byte-0 EOF egyertelmuen 444 (NGX_HTTP_CLOSE), nem keep-alive idle-close; mid-response truncation = KEMENY hiba (reserved status 0), SOHA nem 444. A detect-mod callerek byte-azonosak. A reconnect-arg mindig literal `($host,$port)` (S1). - *Source:* plan + agent (kodolvasas: `waf_match.c:24` WAF_ACTION_444).
79. **2026-06-15 (S16)** — **`waf_reason_header on` GLOBALISAN (enforce vhostokra is)** — TERV-ELTERES a tabla "on"-jatol. Indok: a harness a (reason,status) tuple-t asserteli enforce-ban; ehhez a wire-reason kell non-444-nel, kulonben MINDEN non-444 reason-mismatch-en bukna. 444-nel a kapcsolat zar a header elott -> reason a freeze-time detect-passbol all, enforce-assert status-only. - *Source:* agent (kodolvasas).
80. **2026-06-15 (S16)** — **uri/value-join pozicionalis helyett.** A feed (method,uri) parja 11,880x duplikalt (azonos path eltéro ua/referer/status-szal); a path/args matcher method-fuggetlen (nincs method-filter ezeken a vhostokon) -> a verdikt uri-determinisztikus -> dedup uri/value szerint + join biztonsagos. Az enforce-pass CSAK a covered subseten fut (gyors: ~21k friss connect <15s). - *Source:* agent.
81. **2026-06-15 (S16)** — **a fixture a TELJES covered halmaz, NEM top-N (partner "mind" dontes).** Path 21,224 (35,397 covered feed-sorbol uri-dedupolva) + args 39 + header 160. A `count` mezo CSAK metaadat (riport), assert SOHA nem sulyoz vele. Meret ~3.5 MB (a becsult 4-6 MB alatt a dedup miatt). - *Source:* user (S16 scope-dontes 3).
82. **2026-06-15 (S16)** — **"README korpusz-szekcio" = `docs/threat-model.md` §6.C (planned)->(DONE) + intro frissites; nincs kulon corpus README.** A §6.B MEG "(planned)"-et ir, pedig B leszallt `291621d`-ben (stale) — az introt frissitettem ("A and C are done; B is tracked in honeypot-B-plan.md"), de a §6.B torzset NEM nyultam (C scope-on kivul; partnernek jelezve). - *Source:* agent.
83. **2026-06-15 (S17)** — **scanner_lookup bucket-precedencia = 404 > 403 > 444** (enum WAF_ACTION_404=0; lookup i=0..MAX first-match, waf_match.c:305). KOVETKEZMENY: egy broad 404 szabaly LEMASZKOLJA a szukebb 403/444-et minden atfedo path-on. A generikus .php (404) ezert ~46 phpmyadmin/pma *.php-t 403-rol 404-re visz (blokkolva marad). Minden jovobeli broad-404 lista-edit elott ellenorizd a 403/444 atfedest. - *Source:* agent (clangd).
84. **2026-06-15 (S17)** — **generikus .php = broad catch-all, action 404 (partner-dontes).** Az edge nem szolgal PHP-t (minden .php 404; baseline 0 .php) -> nulla FP-felulet (B FP-gate PASS). Minden uj path-minta 404 (blend-in, §2 hide-the-fingerprint); a php://input args 444 (aktiv-RCE). EDGE-SPECIFIKUS: mas hoston a broad .php FP-veszelyes. - *Source:* user (AskUserQuestion: broad + 404 mindenre).
85. **2026-06-15 (S17)** — **lista-minta NEM tartalmazhat szokozt** (scanner_compile: pattern = sor-eleje az ELSO whitespace-ig; utana opcionalis akcio-token {403,444,404}, kulonben WARN+404). Inline `#` komment a minta-sorban TILOS. Ezert Trinity = `(^|/)Trinity\.txt` (NEM "/nice ports"). - *Source:* agent (waf_match.c:235-282).
86. **2026-06-15 (S17)** — **misc secret-leak cluster BEKERULT** (partner: "tedd bele a misc secret szivargasokat is"): aws/credentials, /credentials, *.env (sendgrid.env-csalad), secrets.json, appsettings.json, /env, /containers/json (Docker API), /server-status, /druid/. Mind 404, tighten-anchored, valos korpusz-probe (szazas hitek), nulla legit ezen az nginx-edge-en. - *Source:* user.
87. **2026-06-15 (S17)** — **lista-edit utan KOTELEZO C re-freeze + (mivel meg nincs push) AMEND** (nem uj commit): a masodik kor (secret cluster) az elso commitba amendelve (`7481833`->`a1bda45`), mert ugyanaz a gap-loop logikai egyseg. A re-freeze 37,804->38,905-re notte a fixture-t (csak 404, nincs uj flip). - *Source:* agent + workflow.
88. **2026-06-15 (S18)** — **config/IaC/secret-leak = BROAD extension-csaladok** (partner AskUserQuestion): `^/.*\.ya?ml$`, `^/.*\.properties$`, `^/.*\.tfstate`, `^/.*\.tfvars$`. Az edge nem szolgal config/IaC formatumot -> nulla FP-felulet (B FP-gate PASS). A `.json` viszont NEM lehet blankett (a `/app.json` baseline-t fogna) -> a distinct .json/dotfile secret-store-okat ENUMERALTAM. Ugyanaz a filozofia mint az S17 broad .php-nal, EDGE-SPECIFIKUS. - *Source:* user.
89. **2026-06-15 (S18)** — **generikus szotar-tail KIHAGYVA** (partner AskUserQuestion: "csak distinct probek"): `/login`, `/home`, `/admin`, `/test`, `/new`, `/old`, `/main`, `/user`, `/api`, `/console`, `*.shtml`, `*.jhtml` NEM kerult be. Indok: ezek prodban legit navigacio lehetnek, es a B FP-gate CSAK a baseline-korpuszt latja, nem a prod-forgalmat. Csak megkulonboztetheto (appliance/secret/framework) probek mentek be. - *Source:* user.
90. **2026-06-15 (S18)** — **UJ commit (`cf244cb`), NEM amend** — a #87-tel (S17 within-session amend) szemben ez kulon session + kulon logikai iteracio (config/IaC klaszter), ezert tiszta uj commit. HEAD origin/main elott 2. - *Source:* agent.
91. **2026-06-15 (S18)** — **stale-fix = NO-OP:** a partner valasztotta a §6.B stale-fixet, de az MAR az S17-ben `(done)` lett (a checkpoint S16 open-question elavult). Atneztem (`grep planned`): a §6 intro + §6.D helyes, §6.B `(done)`. Nem kellett editelni. - *Source:* agent.

---

## 4. Files touched

### (S18) Modified / committed (`cf244cb`, UJ commit)
| Path | What | Status |
|------|------|--------|
| `modules/ngx_http_waf/lists/scanners.list` | config/IaC broad-ext (`^/.*\.ya?ml$`, `^/.*\.properties$`, `^/.*\.tfstate`, `^/.*\.tfvars$`) + ~30 enumeralt .json/dotfile secret-store (credentials/client_secrets/auth/composer/sftp-config/settings/local.settings/.runtimeconfig/env.{json,txt}/appsettings.<env>/.npmrc/.netrc/.htpasswd/.dockerenv/.kube/.composer/.docker-config/Rails config-credentials+master.key/connectionstrings/Web.{Debug,Release}.config/web.config[~.]/settings.py/global.asax/storage-logs/error.log/server-info/nginx_status); Symfony `(^\|/)debug/default/view`; generikus .php -> `^/.*\.php[0-9]?($\|[/.~:])` + bare `^/phpinfo`; 16 appliance fingerprint (WPnBr.dll/Telerik/GponForm/+CSCOL+/metadatauploader/config-getuser/dana-na/dana-cached/mgmt-tm-util-bash/api-sonicos/mifs/CFIDE/sitecore/RDWeb/evox-about/parastable/etc-passwd) | modified (+61/-4) |
| `modules/ngx_http_waf/tests/corpus/regression-vectors.jsonl` | C fixture re-frozen 38,905->40,614 (+1709, mind 404; {404:40,573 403:146 444:55}) | modified |
| `docs/threat-model.md` | §6.A masodik 2026-06-15 iteracios bekezdes (config/IaC + appliance, uncatalogued 21.6->35.3%, exclude-tail indok) + §6.C fixture-szam 38,905->40,614 | modified |
_(regression-headers.jsonl BYTE-AZONOS -> nincs a commitban; args.list NEM valtozott S18-ban.)_

### (S17) Modified / committed (`a1bda45`, amend)
| Path | What | Status |
|------|------|--------|
| `modules/ngx_http_waf/lists/scanners.list` | +wlwmanifest, generikus `^/.*\.php(/|$)`, /bin/sh, /remote/login, /+cscoe+/, Trinity, /hello.world; uj "credential/config/infra-API leaks" szekcio (aws/credentials, /credentials, `^/.*\.env$`, secrets.json, appsettings.json, /env, /containers/json, /server-status, /druid/); a kommentelt /+cscoe+/ jelolt torolve (most aktiv) | modified |
| `modules/ngx_http_waf/lists/args.list` | +`php://input` 444 (uj "PHP RCE" szekcio) | modified |
| `modules/ngx_http_waf/tests/corpus/regression-vectors.jsonl` | C fixture re-frozen 21,263->38,905 vektor ({404:38,864 403:146 444:55}) | modified |
| `docs/threat-model.md` | §3.1 (Trinity/dns-query/hello.world covered), §6 A (2026-06-15 iteracio tablazat+proza+secret-cluster), §6 B (planned)->(done), §6 C (38,905 fixture-szam), §6 intro (A,B,C done) | modified |
_(regression-headers.jsonl byte-azonos -> nincs a commitban; a B/freeze derivatumok + .freeze-tmp gitignore-oltak.)_

### (S16) Created / modified / committed (`2f0c18e`)
| Path | What | Status |
|------|------|--------|
| `modules/ngx_http_waf/tests/replay-client.pl` | `--enforce` mod: `$enforce`+`$conn_hdr`; GetOptions `enforce`; `connect_sock() unless $enforce`; `read_line($prefix)`; `read_response` first-byte 444-probe ('CLOSED' sentinel); `send_request_and_read` enforce-branch (444/0/real); 3x `Connection: $conn_hdr`; STDERR mode-sor | modified |
| `modules/ngx_http_waf/tests/waf-regression-test.conf` | **UJ** — 283xx, 13 vhost (reg-status 28300 waf off + waf_status; detect/enforce par: path 28301/02, args 28303/04, ua 28305/06, referer 28307/08, cookie 28309/10, fakebot 28311/12); `waf_reason_header on` + `waf_bot_block off` globalis; vhostonkent EGY matcher; zero proxy_pass / trusted_proxy / rate / geo; fakebot M3 (crawler+ai_crawler lista + 2 verified_bot) | created |
| `modules/ngx_http_waf/tests/corpus/freeze-regression-fixture.pl` | **UJ** — ketpasszos generator (detect->reason 28301..11, enforce->status 28302..12); dedup uri (path/args) / value (header); covered-subset feed; list-form `system()`; fix `.freeze-tmp/` temp; JSON::PP canonical output | created |
| `modules/ngx_http_waf/tests/corpus/regression-vectors.jsonl` | **UJ** committed fixture — 21,263 path/args frozen vektor (~3.4 MB) | created |
| `modules/ngx_http_waf/tests/corpus/regression-headers.jsonl` | **UJ** committed fixture — 160 ua/referer/cookie/fakebot frozen vektor (~35 KB) | created |
| `modules/ngx_http_waf/tests/run-regression-tests.sh` | **UJ** — harness: nginx -t + `^\s*proxy_pass` assert, start/stop/trap, FP-gate (baseline 28302 reason=none + status 200/404), per-dim enforce-replay + `compare.pl` heredoc (join `key`<->uri/value, (reason,status) tuple, 444 status-only, first-20 DIVERGE), exit 0 iff 0 mismatch | created |
| `.gitignore` | +`corpus/.freeze-tmp/` ignore (a fixture-ok trackeltek) | modified |
| `docs/threat-model.md` | §6.C (planned)->(DONE) + intro "A and C are done; B tracked in honeypot-B-plan.md" | modified |
_(A `.freeze-tmp/` per-run scratch gitignore-olt; scanners.list-et a negativ proba ideiglenesen erintette, VISSZAALLITVA — nincs benne a commitban.)_

### (S14) Created / modified (NOT committed)
| Path | What | Status |
|------|------|--------|
| `src/ngx_http_waf.h` | `loc_conf.reason_header` flag (server_token utan) | modified |
| `src/ngx_http_waf_module.c` | `waf_reason_header` direktiva (FLAG, set_flag_slot); create=UNSET; merge default 0; `ngx_http_waf_reason_header_filter` + `ngx_http_waf_next_reason_filter` static; prototip; postconf-regisztracio (spoof_init utan) | modified |
| `tests/waf-replay-test.conf` | **UJ** — 7 dimenzio-tiszta detect vhost (path 28182/args 28183/ua 28184/referer 28185/fakebot 28186/cookie 28187/status 28190); `waf_reason_header on` http-szinten; no proxy_pass / loopback-only / no trusted_proxy; matcherek CSAK per-vhost; bot_block off (csak ua on) | created |
| `tests/replay-client.pl` | **UJ** — raw-socket HTTP kliens (kind path/header/baseline); S1 cel mindig 127.0.0.1:port; S2 nincs shell; S3 \xNN re-expand csak header-value-ban + CRLF skip; HEAD no-body; keep-alive+reconnect; X-WAF-Reason olvasas; result JSONL | created |
| `tests/run-replay-tests.sh` | **UJ** — harness: nginx start/stop, FP-gate (baseline 0 would_block all-reason), per-dimenzio replay + counter-xcheck, coverage-report (perl), uncovered-export (cap 2000), exit!=0 iff FP-fail; `LIMIT` env passthrough | created |
| `tests/corpus/extract-replay-vectors.pl` | `--ua-vectors`/`--referer-vectors` modok (nyers UA/referer feed, IP-mentes); fo jsonl valtozatlan | modified (S13-bol) |
| `tests/corpus/build-header-fixtures.pl` | **UJ** — fixture-builder (korpusz-feed + kulso pull + szintetikus SQLi -> ua/referer/cookie/fakebot.jsonl; clean()=CR/ctrl strip+chomp+HTML-entity decode); core-perl+JSON::PP | created |
| `tests/waf-stat-test.conf` | `waf_reason_header on` a detect vhostra (28082) | modified |
| `tests/run-stat-tests.sh` | +3 reason-header assert (args-token / none-token / default-off hiany) -> 131/131 | modified |
| `README.md` | korpusz-tooling szekcio (extractor/builder/replay-conf/client/harness + threat-intel/B-plan linkek) + `waf_reason_header` direktiva-sor | modified |
| `.gitignore` | B-derivatumok: fixtures/, replay-*-results.jsonl, fp/coverage report, uncovered.jsonl, ua/referer-vectors.jsonl | modified |
| `tests/corpus/fixtures/` + `replay-*-vectors.jsonl` + `replay-*-results.jsonl` + 3 riport | generalt derivatumok (gitignore-olt; commit-policy lasd §10/Decision #76) | generated |

### (S13) Created / modified (NOT committed — no WAF .c change)
| Path | What | Status |
|------|------|--------|
| `modules/ngx_http_waf/tests/corpus/extract-replay-vectors.pl` | durable perl replay-vektor extraktor (one-pass, label-first, `--collapse-ua`, `--top-excluded`, `--outdir`) | created |
| `docs/threat-intel-sources.md` | header-attack fixture forras-katalogus (deep-research, 8-as shortlist + gap-ek) | created |
| `docs/honeypot-B-plan.md` | B work-stream terv (inspector-reviewed v2) | created |
| `.gitignore` | +`replay-vectors.jsonl`/`.summary.txt` ignore (NEM a teljes `corpus/`) | modified |
| `modules/ngx_http_waf/lists/scanners.list` | +kommentelt "static-extension-cloaked probes" szekcio (nem aktiv) | modified |
| `modules/ngx_http_waf/tests/corpus/replay-vectors.{jsonl,summary.txt}` | gitignore-olt derivatumok (~11MB jsonl, 84,970 sor) | generated |

### (S11) Modified / created / committed (`c426d98`)
| Path | What | Status |
|------|------|--------|
| `modules/ngx_http_waf/src/waf_rate.h` | **UJ** — opaque API (`rate_check`, `rule_select`, `rule_add`, `init_zone`, `overflow`), `ngx_http_waf_rate_rule_t` (rate_num_fp/period_ms/burst_fp/geo_cc), `WAF_RATE_SCALE 1000`; includes waf_rep.h (verdict_t) | created |
| `modules/ngx_http_waf/src/waf_rate.c` | **UJ** — mag: `#if NGX_PTR_SIZE<8 #error` + `_Static_assert(sizeof(ngx_atomic_t)>=8)`; slot{key,state} + hdr{rate_overflow,nslots}; FNV-1a kulcs (family tag + IP, /64 v6, 0->1); `rate_check` (probe+eviction-on-full+token-bucket CAS, uint32 wrap-safe elapsed, bounded retry, fail-open); `rule_select` (geo_valid-gated, first for_geo match else default); `rule_add` (rate=/burst=/for_geo= parse, P6 bounds, max-1-default); `init_zone` (reload-reuse / re-attach / fresh slab-fill margin+backoff); `rate_overflow` getter | created |
| `modules/ngx_http_waf/src/waf_rep.h` | `WAF_REASON_RATE_LIMIT` a FAKE_BOT utan, MAX ele | modified |
| `modules/ngx_http_waf/src/ngx_http_waf.h` | `loc_conf.rate_rules` (ngx_array_t*) | modified |
| `modules/ngx_http_waf/src/waf_status.h` | `main_conf.rate_zone` (ngx_shm_zone_t*) + `stat_shm_t.http_resp_429` | modified |
| `modules/ngx_http_waf/src/ngx_http_waf_module.c` | `#include waf_rate.h`; `waf_reason_str[]` +rate_limit; 2 direktiva (`waf_rate_zone` MAIN azonnali shm-create, `waf_rate_limit`); 2 setter (ordering-EMERG guard); PREACCESS rate-check (method utan, ua_classify elott) + cc_bump guard (M3); `stat_http_block` case 429; merge rate_rules | modified |
| `modules/ngx_http_waf/src/waf_status.c` | `#include waf_rate.h`; FIXED_LINES 96->112; http_resp_429 + rate_overflow render (plain/json/prometheus) + handler `rate_overflow` kiolvasas + 3 renderer-signatura | modified |
| `modules/ngx_http_waf/src/waf_stream.c` | `#include waf_rate.h`; srv_conf.rate_rules + file-static `ngx_stream_waf_rate_zone`; `waf_stream_rate_limit` direktiva+setter; handler atstrukturalva (rep->rate, egyszeri stat-bump, detect-aware); zona size-0 resolve | modified |
| `modules/ngx_http_waf/src/waf_authhttp.c` | `#include waf_status.h`+`waf_rate.h`; reputation_check most `&verdict` (volt NULL); rate-check rep-allow utan; deny `authhttp_deny(r,"rate limit")` + globalis http_blocked[RATE_LIMIT]+http_resp_429 | modified |
| `modules/ngx_http_waf/config` | waf_rate.h a waf_deps-be, waf_rate.c a waf_srcs-be | modified |
| `modules/ngx_http_waf/tests/waf-stat-test.conf` | `waf_rate_zone size=1m`; `/rate`,`/rate-geo` (vhost A); `/rate-detect` (detect vhost); mail loc `waf_rate_limit`; stream 29093 `waf_stream_rate_limit` | modified |
| `modules/ngx_http_waf/tests/run-stat-tests.sh` | +27 eset: HTTP burst->429, XFF-invarians (P5c), detect would_block, stream L4 rate, mail per-Client-IP rate, 3-formatum expozicio, EMERG-guard negativ teszt | modified |
| `sandbox/html/{rate,rate-geo,rate-detect}` | 3 backing fixture (200-as allow-hoz) | created |
| `README.md` | direktiva-tabla 2 sor (HTTP) + 1 sor (stream) + "Rate limiting (token bucket)" szekcio | modified |

### (S10) Modified / created / committed (`24f9145`)
| Path | What | Status |
|------|------|--------|
| `modules/ngx_http_waf/src/waf_geo.c` | OpenSSL includes (evp/pem/bio/err); header-layout `#define`-ok; pinned PEM `static const char[]`; uj `ngx_http_waf_geo_u16` (dedikalt BE 16-bit) + `ngx_http_waf_geo_verify` (dual-sig, accept `==1`, present-slot, snapshot-per-slot, single goto-cleanup, ERR_clear_error); pre-mmap size guard min 4200 + max 512 MiB; verify-hivas a magic check utan | modified |
| `reference/locverify.c` | **UJ** standalone dev-oracle (libc + `-lcrypto`, NEM buildelt a modullal); a libloc verify-semat reprodukalja; `VALID (sigN)`/`INVALID`/error; ugyanaz az accept-fegyelem mint a modul | created |
| `modules/ngx_http_waf/tests/run-stat-tests.sh` | +8 assert: "geo DB signature verification" szekcio — (1) tampered data-byte flip size-derived offseten -> nginx -t fail + verify-log, (2) header-only 4200 -> verify fail, (3) tiny 100 -> too-small guard, (4) real-DB-under-cap sanity | modified |
| `README.md` | "Signature verification (load-time, fail-closed)" al-szekcio a Geo/reputation alatt + a `reference/` sor `locverify.c`-vel kiegeszitve | modified |

_(config + waf_geo.h SZANDEKOSAN VALTOZATLAN — libcrypto mar linkelve a JA4 miatt, `ngx_module_libs` ures.)_

### (S9) Modified / created / committed (`0638343` kod + `1e490d7` doksi)
| Path | What | Status |
|------|------|--------|
| `modules/ngx_http_waf/src/waf_rep.h` | `WAF_REASON_FAKE_BOT` a REFERER utan, MAX ele | modified |
| `modules/ngx_http_waf/src/ngx_http_waf.h` | `verified_bot_cidrs[WAF_UA_LIST_MAX]` + `verified_bot_list[]` sentinel + `fake_bot_block` flag | modified |
| `modules/ngx_http_waf/src/waf_match.c` | `ngx_http_waf_verified_bot_compile` (lazy-alloc) | modified |
| `modules/ngx_http_waf/src/waf_match.h` | prototipus + lazy-alloc komment | modified |
| `modules/ngx_http_waf/src/ngx_http_waf_module.c` | reason_str +fake_bot; 2 command_t; setter; create/merge; PREACCESS fake-bot blokk | modified |
| `modules/ngx_http_waf/lists/verified-crawler.list` + `verified-crawler-local.list` | fixture-listak (loopback KIVUL / BENT) | created |
| `modules/ngx_http_waf/tests/waf-stat-test.conf` | 5 location (fakebot/-ok/-skip/-off/-detect) | modified |
| `modules/ngx_http_waf/tests/run-stat-tests.sh` | +16 eset | modified |
| `sandbox/html/{fakebot,fakebot-ok,fakebot-skip,fakebot-off,fakebot-detect}` | 5 backing fixture | created |
| `README.md` | 2 direktiva-sor + "Verified-bot" szekcio + `$waf_reason` potlas | modified (`1e490d7`) |

### (S8) Modified / created / committed (`3a48d61`)
| Path | What | Status |
|------|------|--------|
| `modules/ngx_http_waf/src/waf_rep.h` | 3 uj reason (ARGS/COOKIE/REFERER) | modified |
| `modules/ngx_http_waf/src/ngx_http_waf.h` | `ngx_http_waf_sig_e` + `sig_list[]`/`sig_re[][]` | modified |
| `modules/ngx_http_waf/src/waf_match.c` + `.h` | `scanner_compile`/`scanner_lookup` generalizalas (caller-owned `re_bucket`) | modified |
| `modules/ngx_http_waf/src/ngx_http_waf_module.c` | reason_str +3; `set_sig_list`; 3 direktiva; merge; 2 helper; PREACCESS args/cookie/referer lanc | modified |
| `modules/ngx_http_waf/lists/{args,cookie,referer}.list` | 3 uj signature-lista | created |
| `modules/ngx_http_waf/tests/{waf-stat-test.conf,run-stat-tests.sh}` | `/sig` + `/sig-detect` + 20 eset | modified |
| `sandbox/html/{sig,sig-detect}` | statikus fixture | created |

### (S6-S7) Modified / committed (`3a6854c`, `a2f367b`)
| Path | What | Status |
|------|------|--------|
| `docs/threat-model.md` | honeypot threat-intel + A-D teszt-program terv | created (S6) |
| `README.md` | pontossag-audit 11 javitas | modified (S6) |
| `waf_match.c` / `module.c` / `waf_spoof.c` / `waf_status.c` / `waf_stream.c` | parser-dedup + 27 nginx-proza doc-komment | modified (S7) |

### Read (for context, S10)
- `modules/ngx_http_waf/src/waf_geo.{c,h}` (teljes), `reference/loctest.c` (oracle-minta), `modules/ngx_http_waf/tests/run-stat-tests.sh` + `waf-stat-test.conf` (eleje).
- Kulcs-acquisition: curl git.ipfire.org gitweb blob_plain + sources.debian.org raw data endpoint; openssl pkey ellenorzes.

### Pending edits (planned, NOT applied)
- _(none)_

---

## 5. Session timeline

### Session 1-4 — 2026-06-12..13
Build-lanc, Phase 0-4, lock-free stats, JA4/ASN/method/detect feature. Vegallapot `c1f8a72`.

### Session 5 — 2026-06-14
Takaritas, 2 review, 2 HIGH geo-OOB + F4/F8 fix, flag_cc, cc_map/magic, honeypot A. KRITIKUS: a "sandbox" az ELES prod box (example.com, :443) — partner LEALLITOTTA.

### Session 6 — 2026-06-14 (detektor-elvetes + dokumentacio)
Detektor-spec megirva majd ELVETVE (adatvezerelten: 99.97% parser-400); `docs/threat-model.md` megirva; README pontossag-audit. Commit `3a6854c`.

### Session 7 — 2026-06-14 (tech-debt takaritas)
parser-dedup (`next_line` helper) + 27 nginx-proza doc-komment; location.db integritas a roadmapra. Commit `a2f367b`. Build fast-target megerositve.

### Session 8 — 2026-06-14 (feature #1: args/cookie/referer signature-blocklist)
Generalizalt scanner compile/lookup; 3 reason auto-extend; 3 direktiva + setter; PREACCESS lanc. Commit `3a48d61`. **77/77** + 6/6 + 0 warning.

### Session 9 — 2026-06-14 (feature #2: CIDR fake-bot verify)
CIDR fake-bot (no DNS); `verified_bot_compile` a waf_match.c-be; 2 direktiva + PREACCESS; ket fixture-lista (peer-re kulcsolt teszt). Commit `0638343` + README `1e490d7`. **93/93** + 6/6. Ket minion tiszta.

### Session 10 — 2026-06-14 (feature #4: location.db load-time alairas-verify)
1. Partner: "Implement the following plan" — feature #4 reszletes terve (ket inspector-kor mar atment rajta). Felmertem a `waf_geo.c`-t (geo_open:36, size-guard:70, magic:106-112, blokk-loop:117-118) es megmertem a valodi DB-t: **63,517,012 byte** -> cap 512 MiB (~8.5x).
2. **Step 0 (kulcs-gate):** a pinned IPFire P-521 pubkey-t curl-lel KET fuggetlen HTTPS forrasbol (git.ipfire.org gitweb + sources.debian.org 0.9.18-3) szereztem byte-azonosan (signing-key.pem SHA-256 `c9b397a2…`); tiszta PEM-blokk SHA-256 `7d927e19…`; openssl megerositette secp521r1/P-521. Megirtam `reference/locverify.c`-t (standalone oracle, purity create). p:minion-runner buildelt+futtatott: **ORACLE GATE PASS** (VALID sig1 / INVALID data-flip / error truncated / 8.5x cap-headroom, 0 warning, semmi forrasmodositas).
3. **Step 1 (modul):** purity replace_content-tel: includes, layout `#define`-ok, pinned PEM literal, `ngx_http_waf_geo_u16` + `ngx_http_waf_geo_verify`, szigoru pre-mmap size guard (min DATA_OFF + max cap), verify-hivas a magic check utan. clangd diagnosztika = csak `ngx_config.h not found` cascade (env-artifakt, NEM hiba). p:minion-builder: PASS, 0 warning, libcrypto feloldva. Pozitiv `nginx -t` a valodi DB-vel: OK.
4. **Step 2 (teszt):** run-stat-tests.sh +8 negativ assert (tampered size-derived offset / header-only 4200 / tiny 100 / cap-sanity). Teljes suite: **101/101** (93+8). Unit **6/6**.
5. **Step 3 (README):** "Signature verification (load-time, fail-closed)" szekcio + `reference/` sor.
6. **Commit `24f9145`** (csak a 4 sajat path stage-elve; `ngxlogs/` KIHAGYVA; kulcs-SHA256-ok a commit-uzenetben). NEM push.
7. Partner: "mehetnek a minyonok". Ket verifikalo minion a VEGLEGES kodon: impl-inspector COMPLETE **16/16**; security-officer find (4 finding) -> verify (0 kihasznalhato, mind SUPPRESSED). Az F1 (error-queue) + F3 (oracle) findingot meg a verify ELOTT javitottam (`ERR_clear_error` + `ERR_error_string_n`), ujraepitettem (0 warning) es ujra-validaltam (oracle + 101/101 + 6/6).
8. Checkpoint frissites.

### Session 11 — 2026-06-15 (feature #3: lock-free per-IP token-bucket rate-limit — roadmap TELJES)
1. Partner: "Implement the following plan" — feature #3 reszletes terve (plan-inspector APPROVE-WITH-CHANGES + security-officer plan-mode 0 CRITICAL mar atment rajta; C1/C2/H1-H3/M1-M3/P1/P3-P6 findingok beepitve).
2. Felmertem a teljes erintett kodot (module.c eleje+vege, waf_rep.h, waf_status.{c,h}, config, waf_stream.c, waf_authhttp.c, waf_geo.c IP-byte switch, tesztek) ES az nginx forrasban: `ngx_atomic_t`=64-bit amd64, `NGX_PTR_SIZE`=8, `NGX_HTTP_TOO_MANY_REQUESTS`=429 (van `ngx_http_error_429_page`!), `ngx_shared_memory_add` size-negotiacio ORDER-FUGGETLEN (a size-0 belepo megkapja a kesobbi meretet), slab overhead ~56 B/lap, `country_add` packolas `(c0<<8)|c1` (== verdict cc16), `reputation_check` minden agon init-eli a verdictet.
3. **Phase 0:** `waf_rate.h` + `waf_rate.c` (mag) megirva; `WAF_REASON_RATE_LIMIT` + lockstep string; config descriptor.
4. **Phase 1:** struktura-mezok (loc_conf/main_conf/srv_conf) + http_resp_429; `waf_rate_zone`/`waf_rate_limit` direktivak+setterek (ordering-EMERG) + STREAM `waf_stream_rate_limit` + zona-resolve + merge.
5. **Phase 2-4:** HTTP PREACCESS integracio (method utan, ua_classify elott) + 429-case; STREAM handler atstrukturalas (egyszeri stat-bump); MAIL verdict+rate+deny; `waf_status.c` 3-formatum render + FIXED_LINES bump.
6. **Build** p:minion-builder-rel (reconfigure az uj .c miatt + ssl.h touch-guard + waf_module target): **PASS, 0 warning** elsore.
7. **Tesztek:** config-test (egy elejtett `}` javitva), majd `run-stat-tests.sh` **128/128** + unit **6/6** zold.
8. **Verifikacio:** impl-inspector COMPLETE **22/22** (0 logikai bug); security-officer find (11 finding) -> verify **0 kihasznalhato defekt** (mind SUPPRESSED; integer-overflow bizonyitottan nem fordul elo).
9. **Commit `c426d98`** (csak sajat path-ok + 3 fixture; `ngxlogs/` KIHAGYVA; NEM push). waf-feature-roadmap + MEMORY.md memoria frissitve (mind a 3 megtartott feature SHIPPED). Checkpoint frissites (ez).

### Session 12 — 2026-06-15 (#3 trust-hatar audit — LEZARVA, nincs kodvaltozas)
1. Partner: "meselj a 3.-rol" (a hatralek #3 pontja = a megosztott `sa`-feloldas kulon audit). Mielott meselek, p:minion-explorerrel felterkepeztem mind a 3 fej kliens-IP / sockaddr trust-hatarat (clangd + Read, no grep).
2. **Adatfolyam-terkep:** HTTP — POST_READ `ngx_http_waf_module.c:433` alap=peer, **:436 trust-dontes** (`trusted_proxy != NULL && x_forwarded_for != NULL` -> `ngx_http_get_forwarded_addr` -> `ctx->client_sa` `:446`), PREACCESS `:839` olvassa, minden check ezt hasznalja (rep `:841`, rate `:930`, fake-bot `:999`, `$waf_country/$waf_asn`). STREAM — `waf_stream.c:214` verbatim peer, nincs XFF/proxy-protocol. MAIL — `waf_authhttp.c:64` `peer_trusted()` (loopback `127/8`,`::1`,AF_UNIX) -> `:82` Client-IP header, kulonben `:88` peer; fail-open `:78` (trusted peer + hianyzo Client-IP -> allow). NINCS kozos resolver, mindharom fej maga donti el a `sa`-t.
3. Partner ket fogalmi kerdese (XFF mi az, `waf_trusted_proxy` mi az) megvalaszolva.
4. Partner: "eleg dokumentalni ha nincs dokumentalva". Atneztem a README-t (`search_for_pattern` *.md): a trust-modell MAR teljesen dokumentalt — HTTP XFF (`:354-360`,`:490-492`,`:810-811`), MAIL loopback gate+`waf off`+fail-open (`:498-521`), STREAM verbatim (`:538-540`), rate canonical IP (`:643-645`). `docs/threat-model.md`-ben NINCS (csak honeypot intel). **Verdikt: nincs doc-gap.**
5. Partner: "de csak ide nekem, ne doksiba" -> konszolidalt 3-fejes trust-modell tabla INLINE atadva (chat), doksiba SZANDEKOSAN nem irva. #3 LEZARVA (Decisions #65).
6. Checkpoint merge (ez, S12). Nincs kodvaltozas, HEAD valtozatlan `c426d98`.

### Session 13 — 2026-06-15 (honeypot START: step 0 + threat-intel + B terv)
1. Step 0: `extract-replay-vectors.pl` (one-pass, label-first) -> `replay-vectors.jsonl` (84,970 vektor), mind a 9 §3 osztaly ±5%. 2. `docs/threat-intel-sources.md` (deep-research header-fixture katalogus). 3. `docs/honeypot-B-plan.md` (ket inspectorral letisztazva). Nincs WAF .c valtozas.

### Session 14 — 2026-06-15 (waf_reason_header feature + honeypot B KESZ)
1. Partner activation: B implementacio a `honeypot-B-plan.md` §8 szerint. Kontextus elolvasva (checkpoint+B-plan+threat-intel).
2. **B1:** extractor kiterjesztve `--ua-vectors`/`--referer-vectors`-szal (raw UA/referer feed, IP-mentes, collapse-tol fuggetlen); lefuttatva (84,970 vektor reprodukalva + 19,041 UA + 1,619 referer).
3. **B2:** 7 kulso fixture curl-lel (`fixtures/raw/`: CRS scanners-ua 241, SecLists UA 2454, bad-referrers 7113, crawler-json 18367, FuzzDB xplatform/oracle/GenericBlind/MySQL); `build-header-fixtures.pl` megirva (clean()=CR/ctrl-strip+chomp+HTML-entity; provenance; fakebot-tokenek a ELO crawler.list/ai-crawler.list-bol) -> ua 21,537 / referer 8,733 / cookie 287 / fakebot 131 JSONL fixture.
4. **B3:** `waf-replay-test.conf` (7 dimenzio-tiszta detect vhost) — config-teszt OK.
5. Partner kozbeszolt 2x: (a) "korpusz referenciakat a README-be" -> Threat-model szekcio tooling-referenciakkal; (b) "a header legyen kapcsolhato, default on csak teszt kozben" -> **`waf_reason_header` feature** (lasd §2 Completed S14): module.c direktiva+header-filter, default OFF, build 0 warning (p:minion-builder), smoke minden dimenzion helyes, default-OFF bizonyitva, +3 assert -> **131/131**, README-sor.
6. **B4:** `replay-client.pl` + `run-replay-tests.sh` megirva p:minion-runnerrel (2 bug fix: HEAD body-hang, CORPUS export); LIMIT=200 smoke PASS. Atneztem a S1/S2/S3 biztonsagi invariansokat — OK.
7. **B5:** teljes sweep (LIMIT=0, hatterben): **FP-gate PASS**; path covered=delta=35397 (pontos xcheck); coverage-meter (secret_vcs 99.8% / php 41.6% / referer ~0% / cookie SQLi 0% / fakebot 100%); 49,155 uncovered, top-2000 export.
8. **B6:** uncovered klaszterezve gap-loop jeloltekke (dynamic-ext .php 127k / wlwmanifest 13k / cgi-bin->/bin/sh 4.3k / php://input 2.1k / Symfony+VPN).
9. `.gitignore` kiterjesztve a results/riport-derivatumokra; README korpusz-szekcio kiegeszitve a klienssel+harness-szel. Partner ELFOGADTA. Checkpoint merge (ez, S14). Partner: kovetkezo lepes UJ contexttel = COMMIT (korpusz-derivatumok igen, results/riport nem).

### Session 15 — 2026-06-15 (commit)
1. Partner: kerulj kepbe (checkpoint elolvasva, 451 sor), majd "a fixtures is mehet fel; kommit utan frissitsd a checkpointot es friss contexttel megbeszeljuk mi van meg hatra".
2. `.gitignore` atallitva purity-val: a 4 feed + `fixtures/` ignore-sorok torolve (most trackeltek); `.cache/` + `ngxlogs/` ignore-sorok hozzaadva. `git check-ignore` igazolta a results/riport/cache/ngxlogs ignore-t.
3. README ket hunkja szetvalasztva (`git diff > patch`, awk-kal levagva a 2. hunkot, `git apply --cached` az 1. hunkra): a `waf_reason_header` direktiva-sor a feature-commitba, a korpusz-tooling szekcio a B-commitba.
4. **Commit (a) `dbee0ce`** waf_reason_header (5 fajl, 77 ins). **Commit (b) `291621d`** honeypot B tooling (26 fajl, 166,858 ins). Mindketto staged-path-okon (NE -A), Bash-bol (mcp-git nem expose-ol commitot); commit-guard: semmi results/riport/cache/ngxlogs. Munkafa tiszta, HEAD origin/main elott 8. NEM pusholva (partner).
5. Decisions #77 + checkpoint merge (ez, S15). Partner friss contexttel dont a tovabbiakrol.

### Session 16 — 2026-06-15 (honeypot C)
1. Partner: "Implement the following plan" — honeypot C terv (enforce-modu, bekommitolt regresszios fixture + harness). A terv mar inspector-jovahagyott (plan-inspector APPROVE-WITH-CHANGES + security-officer triage PASS), minden finding (H1/H2/M1-M4/L2 + 5 guardrail) beepitve.
2. Beolvasva a kulcs-mintak (replay-client.pl, run-stat-tests.sh, run-replay-tests.sh, waf-replay-test.conf, build-header-fixtures.pl) + feed/fixture-formatumok + `.gitignore`. Mind purity/Read.
3. **replay-client.pl edit** (purity, ~7 replace): `--enforce` flag, `$conn_hdr`, init-connect guard, `read_line($prefix)`, first-byte 444-probe, enforce-branch, 3x Connection-header, STDERR mode. `perl -c` OK.
4. **waf-regression-test.conf** (UJ): 13 vhost; `nginx -t` OK; zero valodi proxy_pass (a 2 grep-talalat csak KOMMENT — a harness `^\s*proxy_pass`-t hasznal).
5. **Dontes (kodolvasasbol):** `waf_reason_header on` GLOBALISAN (enforce vhostokra is) kell a tuple-asserthez (Decision #79); uri/value-join pozicionalis helyett, mert a feed (method,uri) 11,880x duplikalt de a matcher method-fuggetlen (Decision #80).
6. **freeze-regression-fixture.pl** (UJ) + **run-regression-tests.sh** (UJ); `perl -c` / `bash -n` OK.
7. **Freeze futtatas:** regression-nginx indit -> generator (2 perc, ~170k detect + ~35k enforce keres) -> 21,263 path/args + 160 header frozen vektor. Verifikalva: minden reason!=none, status in {404,403,444}, no-PII mezo. ("Wide character" warning = pre-existing detect-replay, a covered ASCII-ertekeket nem erinti.)
8. **Harness elso futas BUKOTT** egy bugon: a `compare.pl` a result-fajl join-mezojet `$d->{$key}`-vel olvasta, de a replay-client kimenetben a mezo neve literalisan `key` (nem uri/value). Javitva (purity), ujrafuttatva.
9. **Harness: 9/9 PASS, minden dim 100% frozen-match, ~20s, exit 0.** End-to-end konzisztencia bizonyitva.
10. **Negativ proba:** `(^|/)\.env` kikommentelve a scanners.list-ben -> harness path-dim FAIL, 6300 vektor `got=(none,404)` divergencia, exit 1; visszaallitva -> zold. Regresszio-erzekenyseg bizonyitva.
11. **unit 6/6 + stat 131/131** valtozatlanul zold (a C nem erinti oket).
12. **Dokumentacio:** `docs/threat-model.md` §6.C (planned)->(DONE) + intro frissites (purity).
13. **`.gitignore`** `.freeze-tmp/` ignore. **COMMIT `2f0c18e`** (8 fajl staged-path, NEM -A; Bash, mcp-git nem expose-ol commitot); show-stat igazolta a pontos 8 fajlt. Munkafa tiszta, HEAD origin/main elott 9. NEM pusholva (partner). Nincs arva nginx.
14. Decisions #78-82 + checkpoint merge (ez, S16).

### Session 17 — 2026-06-15 (gap-loop + §3.1 + misc secret-leaks)
1. Partner: "jojjon a 2+3" (gap-loop B6 + scanners.list §3.1). Beolvasva: scanners.list/args.list/threat-model §3.1+§6/honeypot-B-plan + a lemezen levo replay-uncovered.jsonl (top-2000) a pontos mintakhoz.
2. clangd: scanner_compile akcio-parser (pattern=elso whitespace-ig; no-token=404) + scanner_lookup precedencia (404>403>444, WAF_ACTION_404=0). Ez elorejelezte a phpmyadmin 403->404 flipet.
3. AskUserQuestion: generikus .php = "broad" + akcio = "404 mindenre" (php://input args 444).
4. purity-editek (1. kor): scanners.list (wlwmanifest, generikus `^/.*\.php(/|$)`, /bin/sh, /remote/login, /+cscoe+/, Trinity, /hello.world; kommentelt /+cscoe+/ torolve) + args.list (php://input 444).
5. B harness (full sweep): FP-gate PASS; coverage php 41.6->99.2, wp 89->99.5, phpadmin 15->98.5.
6. C re-freeze (regression-nginx + freeze-regression-fixture.pl): 21,263->37,804; git-diff: ~46 phpmyadmin/pma *.php 403->404 flip (vart, benign); Trinity covered (a fixture a kodolt feed-uri-t tarolja -> grep-artefakt). run-regression-tests.sh 9/9; unit 6/6 + stat 131/131.
7. threat-model doksi (§3.1/§6 A/B/C/intro) frissites; COMMIT `7481833`.
8. Partner: "tedd bele a misc secret szivargasokat is". 2. kor: scanners.list credential/config/infra-leak cluster (9 minta). B FP-gate PASS (uncatalogued 14.1->21.6); C re-freeze 37,804->38,905; 9/9; unit+stat valtozatlan. Doksi §6 A/C frissites. Commit AMEND -> `a1bda45`.
9. Decisions #83-87 + checkpoint merge (ez, S17).

### Session 18 — 2026-06-15 (gap-loop iteracio 2: config/IaC + appliance fingerprints)
1. Partner: "mi van meg hatra?" -> elolvastam a teljes checkpointot (557 sor, 3 reszlet). Megallapitas: feature-roadmap (1-4) TELJES, honeypot A/B/C kesz, csak D az erdemi hatralek; tobbi open-ended karbantartas.
2. AskUserQuestion (irany): a partner a 3 karbantartasi iranyt valasztotta (stale-fix + tovabbi gap-loop + scanners.list bovites), honeypot D KIHAGYVA.
3. Beolvasva: scanners.list, args.list, replay-uncovered.jsonl (top-2000 jelolt-banya, lemezen), threat-model §6.A/B/C/D. Stale-fix kiderult: a §6.B mar S17-ben `(done)` -> NO-OP (Decision #91).
4. A banalyabol klaszterek: domináns config/secret/IaC-leak (~tobb ezer hit), Symfony debug (partner-kert), megkulonboztetheto appliance/VPN/RCE fingerprintek; FP-veszelyes generikus szotar-tail.
5. AskUserQuestion (2 kerdes): config-leak breadth = BROAD extension-csaladok; generikus tail = KIHAGYNI (server-page extek sem). Decisions #88-89.
6. **scanners.list editek** (purity, 4 replace): (Op1) generikus .php -> `.php[0-9]?($|[/.~:])` + bare /phpinfo; (Op2) Symfony /debug/default/view; (Op3) 16 appliance fingerprint; (Op4) credential szekcio broad-ext + ~30 enumeralt secret. Ellenorizve a teljes editált lista.
7. Beolvastam a C harness (`run-regression-tests.sh`) + freeze script (`freeze-regression-fixture.pl`) fejet a pontos minion-utasitashoz (a freeze FUTO regression-nginx ellen fut 283xx-en, kulon a B 281xx-tol; PATH_FEED = replay-vectors.jsonl).
8. **p:minion-runner** (1 db, ~7.3 perc): STEP1 PCRE compile clean; STEP2 B FP-gate PASS (uncatalogued 21.6->35.3%, appliance 100%, php 99.9%, secret_vcs 99.8%); STEP3 C re-freeze 38,905->40,614 ({404:40,573 403:146 444:55}); STEP4 C harness 9/9 0 DIVERGE; STEP5 unit 6/6 + stat 131/131; STEP6 diff (scanners.list +61/-4, regression-vectors.jsonl +1709, headers byte-azonos). Nincs arva nginx.
9. **doksi** (`threat-model.md` §6.A masodik iteracios bekezdes + §6.C fixture-szam) purity-val.
10. **COMMIT `cf244cb`** (3 fajl staged-path, NEM -A; Bash, mcp-git read-only). git show igazolta a pontos 3 fajlt; munkafa tiszta, HEAD origin/main elott 2. NEM push (partner).
11. Decisions #88-91 + checkpoint merge (ez, S18).

---

## 6. Mental model / non-obvious context

### (S17) Uj — gap-loop / lista-bovites
- **scanner_lookup precedencia = 404 > 403 > 444** (enum WAF_ACTION_404=0, lookup i=0..MAX first-match, waf_match.c:305). Egy BROAD 404 szabaly LEMASZKOLJA a szukebb 403/444-et atfedo path-on -> a generikus .php ~46 phpmyadmin/pma *.php-t 403-rol 404-re vitt (blokkolva marad). Jovobeli broad-404 edit elott nezd a 403/444 atfedest.
- **lista-minta NEM tartalmazhat szokozt** (scanner_compile: pattern = sor elejetol az ELSO whitespace-ig; utana opcionalis {403,444,404} akcio-token). Ezert Trinity = `(^|/)Trinity\.txt` (NEM "/nice ports"). Inline `#` komment a minta-sorban TILOS (a parser akcio-tokennek venne -> WARN).
- **a fixture a KODOLT feed-uri-t tarolja** (pl. `Tri%6Eity`, `/cgi-bin/.%2e/.../bin/sh`), NEM a dekodolt r->uri-t amit a WAF matchel. Ezert egy `grep Trinity` a fixture-on 0-t adhat MIKOZBEN a vektor covered (a dekodolt forman matchel). Coverage-ellenorzeshez a kodolt formara grepelj.
- **`^/bin/sh$` alacsony hozam:** a mely cgi-bin traversal (`/cgi-bin/.%2e/.../bin/sh`) nagy reszet az nginx request-line parser mar 400-azza (above-root traversal -> invalid request, §4), igy sosem er PREACCESS-ig; csak a kiegyensulyozott traversal normalizal `/bin/sh`-ra (1 vektor). Helyes szabaly, de a tomeget a parser fogja.
- **broad .php FP-biztonsag CSAK ezen az edge-en:** a baseline (/, app.css, app.json, favicon, robots, sitemap) 0 .php; az edge minden .php-t 404-ez; nincs legit PHP-app -> nulla FP-felulet (B FP-gate bizonyitotta). Mas hoston a generikus .php FP-veszelyes lenne.
- **lista-edit utan a C fixture-t UJRA kell freezelni** (futo regression-nginx + freeze-regression-fixture.pl), kulonben a harness a regi verdikteken bukik. A secret-cluster re-freeze csak 404-et adott (nincs uj flip). A B (281xx) es C (283xx) harness kulon nginx-et indit (kulon pid-fajl) -> nincs utkozes/arva; az orphan-check `pgrep sbin/nginx` mindig sajat bash-soron is talal (false-pozitiv), `pgrep -c` count-tal szurd.

### (S16) Uj — honeypot C enforce-regresszio
- **444 a kliens-oldalon = byte-0 connection close**, NEM HTTP status a droton. Az nginx NGX_HTTP_CLOSE-ra NULLA valasz-byte-tal zar; a replay-client `--enforce` ezt szintetizalja 444-re (first-byte probe: nincs byte -> 444). FONTOS arnyalat: az nginx a 444-et `499`-kent LOGOLJA (S6 note), de a kliens 444-et lat — a harness a kliens-oldali 444-re asserteli.
- **A (reason,status) tuple-assert enforce-ban MEGKOVETELI a `waf_reason_header on`-t az enforce vhoston** (Decision #79). 444-nel nincs header a droton (kapcsolat zar) -> a reason a freeze-time detect-passbol all, az enforce-assert 444-nel STATUS-ONLY.
- **A feed (method,uri) parja 11,880x duplikalt** (azonos path eltero ua/referer/status-szal). De a path/args matcher CSAK a uri-t nezi (nincs method-filter ezeken a vhostokon) -> a verdikt uri-determinisztikus -> dedup uri szerint biztonsagos. EZERT pozicionalis join helyett uri/value-join + covered-subset enforce-pass.
- **A replay-client kimenet join-mezoje literalisan `key`** (= uri path-nal / raw_value header-nel), NEM `uri`/`value`. A fixture viszont `uri`/`value`-t hasznal. A `compare.pl`-ben a fixture oldal `$d->{$key}`, a result oldal `$d->{key}` — ezt elnezni = minden vektor mismatch (elso futas igy bukott).
- **args matcher action = tobbnyire 444** (XSS-payload query-k -> connection close); a covered args 39-bol 38 -> 444, 1 (union-select) -> 403. cookie: a 3 szintetikus marker -> 444 (`<script>`) / 404 (sqlmap) / 403 (acunetix). fakebot -> mind 403.
- **"Wide character in print" warning a detect-passban** (replay-client.pl record_result, header-feed UTF-8 ertekek) = PRE-EXISTING, kozmetikai (a B harness is produkalja); a covered ASCII-ertekeket nem korrumpalja (a harness 100% frozen-match-e ezt bizonyitja). A NEM-covered (reason=none) wide-char sorok ugyse kerulnek a fixture-be.
- **A nginx -t zero-proxy_pass assert `^\s*proxy_pass`-t hasznal** (sorkezdo direktiva), NEM bare `grep proxy_pass` — kulonben a conf-header KOMMENTJEIBEN levo "proxy_pass" szo ("ZERO proxy_pass...") false-positive-ot adna (a sima grep 2-t talal).
- **A freeze a covered-subset feed-et a `.freeze-tmp/`-be irja FIX nevvel** (`subset-<dim>.feed`, `<dim>` kod-kontrollalt listabol), SOHA nem uri/value-bol derivalva (security #2); a kliens-spawn list-form `system($^X, $client, ...)`.

### (S14) Uj — waf_reason_header + B replay
- **Detect modban `$waf_reason` a WOULD-BLOCK okot mutatja, nem "none"-t.** `ngx_http_waf_finalize_decision` (module.c:636) a detect-agon `ctx->reason = reason; verdict_set = 1;` MIELOTT NGX_DECLINED-et ad; a `$waf_reason` getter (`:2084`) ezt rendereli. Declined-tiszta keres -> `ctx->reason` marad 0 -> "none". EZ teszi lehetove az X-WAF-Reason per-vektor attribuciot detect modban (a terv hibajat — detect-counter vs per-vektor uncovered — ez oldja fel).
- **`waf_verified_bot` osztaly-token = `crawler` vagy `ai_crawler` (ALULVONAS, NEM kotojel!).** A `$waf_type` viszont "ai-crawler" (kotojel). A setter (`:1428-1434`) `ai_crawler`-t var; `ai-crawler` config-hiba.
- **`waf_reason_header` build = FAST-TARGET (meglevo .c szerkesztes, NEM uj .c):** `cmake --build build --target waf_module`, NINCS `./configure` reconfigure, NINCS ssl.h touch. (Uj .c FAJL kell csak reconfigure-t.)
- **purity `create_text_file`/`replace_content` param = JSON-transport:** a JSON-valid escape-ek (`\n \r \t \" \\ \/ \uXXXX`) DEKODOLODNAK, az ervenytelenek (`\x \s \d \.` stb.) literalisan atmennek. KOVETKEZMENY: `\n` egy KOMMENTBEN szettori a sort (ez buktatott el a build-header-fixtures-nel); HTTP `"\r\n"` stringben mukodik (valos CRLF lesz, ugyanaz a byte); ahol LITERAL backslash kell a forrasban (pl. perl regex `\\x`), a paramban DUPLAZNI kell. A minion (built-in Write) sajat kontextusban iteralva ezt elnyeli.
- **replay-client byte-soros `read_line`** a perl IO-bufferen megy (nem syscall/byte), ezert ~208k keres elfogadhato ido alatt lefut; a keep-alive over-read a kovetkezo valaszhoz a bufferben marad (helyes pipelining); reconnectnel friss handle.
- **`build-header-fixtures.pl` `clean()`:** `chomp` KELL (kulonben a `read_list` ertekek sorvegi `\n`-t hordoznak -> a fakebot-regex es minden fixture elromlik); a korpusz-UA-kban a HTML-entity (`&#39;` stb.) SZANDEKOSAN marad (nyers korpusz); a SecLists entitasok dekodolva.
- **B coverage != FP/TP pass-fail:** az FP-gate az egyetlen hard assert; a coverage trend-jel. Az X-WAF-Reason covered-szam PONTOSAN egyezett a would_block delta-val (path 35397) — a technika es a counter egymast hitelesiti.
- **A B-derivatum `key` mezojeben elofordulo IP** (pl. `127.0.0.1`, `203.0.113.10` UA/referer-ben) = TAMADO-szallitotta header-tartalom, NEM `remote_addr` — IP-mentessegi invarians ALL (az extractor sosem emittal field-0-t).

### (S11) Uj — rate-limit
- **`ngx_shared_memory_add` size-negotiacio ORDER-FUGGETLEN:** ha egy zona size-0-val letezik es kesobb valaki size>0-val adja, a size-0 belepo MEGKAPJA a meretet (`if(size==0) shm.size=size`); az `init` callbacket barki beallithatja ugyanarra a zona-objektumra. Ezert mindegy hogy a http{} vagy a stream{} blokk van elobb — a HTTP ad meretet+init-et, a STREAM/MAIL size-0 resolve. NINCS zona-ordering EMERG (H3). De ha a http SOHA nem deklaralja a `waf_rate_zone`-t, a stream size-0 resolve egy size-0/init-NULL zonat ad -> zona->data NULL -> rate_check **fail-open** (stream rate-limit csendben no-op a zona nelkul; dokumentalva).
- **A `waf_rate_limit` ordering-guard a HTTP setterben** (`wmcf->rate_zone==NULL` -> EMERG) — ugyanaz a minta mint a `limit_req` (zona deklaracio a hasznalat ELOTT). A `waf_rate_zone`-t a setter AZONNAL letrehozza (`ngx_shared_memory_add` + `zone->init`), NEM a postconfiguration-ben (a stat-zona azert van postconf-ban mert nvhost-szamot var; a rate-zona meretet a direktiva adja).
- **EGY bucket IP-nkent, megosztva minden location + L4 + mail kozott** — a kulcs CSAK az IP (nem location/rule). Ket location kulonbozo rate/burst-tel UGYANAZON a slot-on operal (a token-szam kozos, a cap location-fuggo). Szandekos egyesitett per-IP budget. **Teszt-kovetkezmeny:** loopback bucket kozos a `/rate`, `/rate-detect` ES a stream 29093 kozott -> a HTTP burst-teszt leuriti, a detect+stream teszt erre tamaszkodik (mar ures bucket). A teszt-sorrend ezert szamit.
- **Token-bucket CAS reszletek:** `state = (ts32<<32)|tokens_fp32`; `memzero -> ts=0 -> elso erintes huge elapsed -> burst-ig telik` (nincs first-touch flag); `elapsed` uint32 KULONBSEG a 64-bit promote ELOTT (a ~49-napos `ngx_current_msec` wrap fail-safe = full refill); `new_ts` csak `added>0` eseten ugrik (kis ratak sub-period elapsed-jet megorzi, L1); bounded 16 CAS-retry majd fail-open; `allow = tok>=SCALE`, sub `SCALE`.
- **Eviction-on-full:** PROBE_MAX=32 ablak; a legnagyobb wrap-safe kor (`now32-ts` uint32, NEM min-ts) slotot evikaljuk; a jelolt KULCS-at lokalisba snapshoteljuk; SINGLE-SHOT evict-CAS (retry nelkul) — ha a kulcs kozben valtozott, a CAS elbukik -> `rate_overflow`++ + fail-open; sikeres evict utan `state=0` plain store (uj tulaj teli bucketrol indul, a found-loop CAS-ara bizva). MIN_SLOTS=64 (kisebb zona = EMERG).
- **Slab zona-feltoltes:** `margin = sizeof(pool) + pages*128 + 2*pagesize` (128/lap >2x a valos ~56) -> elso `ngx_slab_alloc` sikeres (nincs "no memory" log-zaj); ha megis NULL, `n -= n/8+1` backoff. `n = hdr->nslots`, `idx = h % n`, `(idx+p)%n` — sosem OOB.
- **`_Static_assert(sizeof(ngx_atomic_t)>=8)`** a load-bearing 64-bit guard (`__STDC_VERSION__>=201112L` ala; a build C11+, lefordult -> a packed CAS biztonsagos); a `#if NGX_PTR_SIZE<8 #error` csak masodlagos.
- **429 RENDELHETO** phase-handlerbol: az nginx core-nak van `ngx_http_error_429_page` (NGX_HTTP_LAST_4XX=430), igy a PREACCESS-bol visszaadott `NGX_HTTP_TOO_MANY_REQUESTS` rendes 429-oldalt ad (a spoof-filter az Apache-oldalt teszi ra, a teszt csak a kodot nezi).
- **rule_select H2-csapda:** SOHA `&& verdict.country` (egy tomb non-NULL ptr-re bomlik -> mindig igaz); a kapu szigoruan `geo_valid && cc16!=0`. Loopback IP-nek nincs geo-rekordja -> `for_geo` SOSEM illeszkedik loopbackre -> a teszt csak parse-ot + default-fallbackot fed (a valodi for_geo-szelekcio loopbackkel nem tesztelheto).
- **Build: UJ .c -> nginx `./configure` ujrafuttatas KELL** (a `waf_module` fast-target onmaga NEM eleg, mert az objs/Makefile nem tudna a `waf_rate.o`-rol). A reconfigure pontos sora az nginx forras `objs/ngx_auto_config.h` `NGX_CONFIGURE` define-jabol nyerheto; utana ssl.h touch-guard, majd `cmake --build build --target waf_module`. (A memoria "waf-module-build-recipe" mar rogziti: "new .c needs reconfigure".)

### (S10) Uj
- **libloc verify-sema (byte-exact, libloc 0.9.18 `src/database.c`):** ECDSA P-521 (secp521r1) + SHA-512; `EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey)` — a NULL digest miatt OpenSSL SHA-512-t valaszt egy P-521 kulcshoz. **Dual signature** (kulcs-rotaciohoz): verify sig1; ha invalid, sig2; **accept ha BARMELYIK valid** (egyik sem hamisithato a privat kulcs nelkul -> rotacio-tolerancia, nem gyengeseg).
- **Hash-uzenet sorrend:** `magic (8 B)` ++ `header (4192 B) a copy-local [60,4160) bytes-okkal NULLAZVA` (mindket u16 hossz + mindket sig-blob; a padding [4160,4192) NEM nullazott) ++ `a fajl tobbi resze (file-offset 4200..EOF)`. File-abszolut: sig1_len base+68, sig2_len base+70, sig1-blob base+72, sig2-blob base+2120, data base+4200.
- **EGY koordinatarendszer:** live-DB olvasas file-abszolut `base+N`; a stack header-masolat copy-local 0..4192, `copy-local N == base+8+N`; zero-regio copy-local [60,4160). (Decisions #58.)
- **u16 olvasas DEDIKALT BE 16-bit** (`(p[0]<<8)|p[1]`), NEM a 32-bit reader — az lenyelne a szomszedos hossz-mezot (a sig1_len/sig2_len egymas mellett pakolt).
- **Accept-fegyelem (a kontroll BIZTONSAGA itt van):** `valid` init 0; `valid=1` CSAK ha egy PRESENT slot `EVP_DigestVerifyFinal == 1` (NEM >0, NEM !=0 — a 0=rossz-alairas es <0=hiba mind reject). Present slot iff `1 <= len <= 2048`; mindket slot 0 = "not signed" reject; SOSE Final ures slotot.
- **Snapshot-fegyelem:** pontosan EGY elo snapshot egyszerre — `EVP_MD_CTX_copy_ex(snap, base_ctx)` a NEM-finalizalt base ctx-bol, Final, majd free-and-NULL a kovetkezo elott; copy_ex MINDIG a base ctx-bol (sose finalizalt snapshotbol) -> a goto-epilogue nem tud double-free-elni. Single goto-cleanup minden agon (incl. success) felszabaditja a base ctx-et, snapshotot, EVP_PKEY-t, BIO-t.
- **`ERR_clear_error()` a verify entry-n** (a not-signed reject utan, az elso OpenSSL hivas elott): igy a `failed:` agon drainelt elso hiba (`ERR_get_error` + `ERR_error_string_n`) garantaltan EBBOL a verifybol valo, nem stale (S10 F1 fix).
- **A verify az ELSO gate a magic check UTAN, a blokk-loop ELOTT** (post-mmap): linearisan olvas, semmi blokk-offsetet nem trust-ol; a pre-mmap guard mar garantalja `size >= DATA_OFF`. Reject-en `geo_open` NULL-t ad -> a mar regisztralt pool-cleanup munmap-eli a mappinget.
- **Size guard PRE-mmap marad** (waf_geo.c:70 helyen): `size < DATA_OFF (4200)` reject (a `size - DATA_OFF` ne wrap-eljen, `size` unsigned) ES `size > MAX_SIZE (512 MiB)` reject (oversized fajl ne tudja a reloadot hashelessel megakasztani). A cap a mert valodi DB-hez kotve (Decisions #59).
- **`config` + `waf_geo.h` VALTOZATLAN:** a libcrypto mar linkelve a JA4 (waf_ja4.c EVP-t hasznal) miatt; `ngx_module_libs` ures. Az EVP_*/PEM_*/BIO_*/ERR_* szimbolumok link-time feloldodnak.
- **Kulcs-acquisition trukkok:** a GitHub mirror (`raw.githubusercontent.com/ipfire/libloc`) 404 (nincs ott a repo); a mukodo forrasok: git.ipfire.org gitweb `?p=location/libloc.git;a=blob_plain;f=data/signing-key.pem;hb=HEAD` ES sources.debian.org `data/main/libl/libloc/0.9.18-3/data/signing-key.pem`. A 374-byte fajl 2 komment-sor + a PEM-blokk; a PEM-reader a vezeto komment-sorokat atlepi, de a modulba CSAK a tiszta armor-blokkot (268 byte) agyaztam.
- **clangd a waf_geo.c-n:** 21 diagnosztika, mind `ngx_config.h not found` cascade — env-artifakt (a clangd-nek nincsenek meg az nginx `-I` flag-jei ehhez az out-of-tree modulhoz), NEM valos kodhiba. A valodi ellenorzes a cmake build.
- **`-Werror=comment` AKNA tovabbra is el:** a base64 PEM-sorok `/` karaktereket tartalmaznak de string-literalban (nem komment), igy nem trigger; a kommentekben kerultem a `/*` szekvenciat.

### (S13) Uj (honeypot)
- **A §3 taxonomia-osztaly != `scanners.list` lefedettseg** (pl. `php`-nek nincs altalanos `\.php` szabaly a listaban) -> B egy COVERAGE meter; az uncovered-export a §6/A gap-loop bemenete.
- **`http_scanner_path[action]` (404/403/444) NEM no detect modban** (csak enforce; a detect-ag korabban return-ol, `module.c:1021-1046`) -> detect = csak az aggregat `http_would_block_scanner_path`.
- **A counterek NEM nullazodnak `nginx -s reload`-ra** (shm struct verbatim ujrahasznalva, `module.c:2244-2248`) -> delta-snapshot az EGYETLEN reset (mint `run-stat-tests.sh` `assert_delta`).
- **PREACCESS first-match-wins** (reputation->method->rate->UA-bot->fake-bot->scanner-path->args->cookie->referer) -> a replay-dimenziokat izolalni kell: **bot_block off** a non-UA vhostokon + benign UA, kulonben a ~30% ures-UA `empty_ua`-ba megy a path-jel helyett.
- **plain counter-kulcsok:** `http_would_block_<reason>` (reason = `waf_reason_str[]`: scanner_ua/empty_ua/scanner_path/asn/method/args/cookie/referer/fake_bot/rate_limit/blocklist/geo/geo_whitelist/flag/allowlist).
- **A korpusz CSAK UA+Referer-t orzi** (nginx combined log); Cookie/Host/XFF nincs -> header-fixture KULSO forrasbol (`docs/threat-intel-sources.md`); a raw UA-hoz `--collapse-ua` NELKUL kell ujrageneralni.
- **replay-biztonsag (security-officer):** raw-socket perl kliens, a kapcsolat-cel MINDIG `127.0.0.1:<port>` (soha a vektorbol); absolute-form/`CONNECT` URI skip+count; `\xNN` re-enkod CSAK az adott header-value-ba (per-header CRLF framing-invarians); fixture/korpusz bajt SOHA shell-wordbe/config-DSL-be.

### (S9) Uj
- **XFF MOST ALLOW-DONTEST KAPUZ:** a fake-bot allow-t kot a kliens IP-hez; `sa = ctx->client_sa ?? r->connection->sockaddr`; `client_sa` csak trusted-proxy peertol XFF. A blokk megkerulesehez a publikalt tartomanyba kellene SPOOFOLNI -> TCP-n lehetetlen trusted proxy nelkul. A `waf_trusted_proxy` CSAK valodi CDN/LB legyen, es a front proxy IRJA FELUL az XFF-et.
- **`ngx_cidr_match(sa, arr)`** = `NGX_OK` match / `NGX_DECLINED`. O(n), request-enkent. ai_crawler lista nagy lehet + GPTBot-spam a teljes scant kenyszeriti (elfogadott opt-in trade-off).
- **PREACCESS class-guard OOB-vedelem:** `(ua==CRAWLER||ua==AI_CRAWLER)` short-circuit a `verified_bot_cidrs[ctx->ua]` index BAL oldalan (REGULAR/EMPTY >= WAF_UA_LIST_MAX).
- **lazy-alloc:** `cidr_add` csak az elso sikeres push-nal allokal -> ures fajl = NULL = class skip.
- **PREACCESS sorrend:** IP reputation -> method -> UA classify -> bot_block -> **fake-bot** -> scanner path -> args/cookie/referer.

### (S8) Uj
- **A reason-counterek AUTO-EXTENDELNEK:** uj `WAF_REASON_*` (a MAX ele) kiterjeszt MINDEN counter-tombot + mind a render-loopot + a gettert; az EGYETLEN kezi pont a `waf_reason_str[]` (sorrend = enum-ordinal). A status-buffer sizing is MAX-bol szamol.
- **`ngx_unescape_uri(&dst,&src,len,0)`** %XX->byte HELYBEN; `+` NEM szokoz (type 0) -> teszt `%20`-szal. A scanner az nginx-dekodolt `r->uri`-t matcheli; args/Cookie/Referer nyers -> dekodolunk.
- **Cookie = generic header-walk** (verzio-fuggetlen, tobb headert kezel); Referer = `r->headers_in.referer` slot; args = `&r->args`.

### (S6-S7) Megorzott
- **A detektor-elvetes tanulsaga:** adat > intuicio; nezd meg mit csinal MAR a kod.
- **nginx a `444`-et `499`-kent logolja** (closed, 0 byte).
- **Build fast-target MUKODIK:** `cmake --build build --target waf_module` meglevo .c-hez — rebuild + auto-copy `sandbox/modules/`-be; NEM kell ssl.h touch ehhez a targethez.
- **`-Werror=comment`:** SOHA `/*` egy blokk-kommenten BELUL.
- **Doc-konvencio:** publikus fv doksi a .h prototipusnal; statikus helper a .c-ben; 0 Doxygen.

### (S1-S5) Megorzott
- **BUILD = CMake super-build** (`build/nginx_ext-prefix/src/nginx_ext` = $NGX). Fast-target a fo ut; a lassu ut: `touch <ssl.h-k> && make -C $NGX modules`.
- **OpenSSL-rebuild trap:** `./configure` UTAN `touch <ssl.h-k>` a `make` ELOTT. Uj .c -> ./configure. SOHA bare `make`.
- **Teszt-harness:** `sandbox/sbin/nginx` + `sandbox/modules/*.so`; stop+start; portok 28xxx/29xxx/28443.
- **FAZIS-CSAPDA:** `return` a REWRITE-ban fut a PREACCESS ELOTT -> STATIKUS fixture a method/sig teszthez.
- **STREAM nem latja az shm structot** -> opaque void* helperek.
- **promtool/swaks NINCS** (curl/jq/nc/xz/openssl/shellcheck/perl/python3 VAN). nproc=32.

---

## 7. Tooling & environment

- **Active MCP servers:** mcp-purity (MINDEN fajl edit/read/find), mcp-git (branch=main, read-only ops + a commit Bash-bol), mcp-clangd (C-nav; `ngx_config.h not found` artifakt NEM hiba), ai-soul (memoria).
- **Active minions used (S16):** _(none)_ — a C tisztan teszt-tooling (nincs C-forras valtozas, nincs reconfigure/build), igy minion-builder/inspector nem kellett; minden edit inline purity-val, a freeze/harness/tesztek Bash-bol. (A terv-fazis inspectorai — plan-inspector + security-officer triage — mar a terv-keszitesnel lefutottak, ezen sessionon kivul.)
- **Active minions used (S14):** p:minion-builder x1 (waf_reason_header fast-target, 0 warning + config-teszt); p:minion-runner x1 (replay-client.pl + run-replay-tests.sh megiras+smoke, 2 bug fix: HEAD body-hang, CORPUS export; LIMIT=200 smoke PASS).
- **Active minions used (S11):** p:minion-builder x1 (reconfigure + waf_module target, 0 warning elsore); p:minion-impl-inspector x1 (COMPLETE 22/22); p:minion-security-officer x2 (find -> verify, 0 kihasznalhato defekt, 11 finding mind SUPPRESSED).
- **Active minions used (S10):** p:minion-runner (oracle build+ketiranyu validacio); p:minion-builder x2 (waf_module fast-target, 0 warning); p:minion-impl-inspector x2 (COMPLETE 16/16, post-fix recheck); p:minion-security-officer x2 (find -> verify, 0 kihasznalhato defekt).
- **Build/test commands of record:**
  - meglevo .c: `cmake --build build --target waf_module` (fast-target, auto-copy sandbox/modules/-be) — buildet a p:minion-builderre bizd.
  - **UJ .c (S11): reconfigure KELL elobb** — `cd build/nginx_ext-prefix/src/nginx_ext && ./configure <NGX_CONFIGURE-sor az objs/ngx_auto_config.h-bol>` majd ssl.h touch-guard, majd `cmake --build build --target waf_module`. A pontos configure-sor a `--add-dynamic-module=.../modules/ngx_http_waf`-fal vegzodik.
  - oracle (S10, manualis): `cc -O2 -Wall -o /tmp/locverify reference/locverify.c -lcrypto`
  - JA4 unit: `bash modules/ngx_http_waf/tests/unit/run-unit-tests.sh`
  - integracio: `bash modules/ngx_http_waf/tests/run-stat-tests.sh`
  - nginx config-test: `sandbox/sbin/nginx -p .../sandbox/ -c .../tests/waf-stat-test.conf -t`
- **Key env:** bundled OpenSSL 3.5.7, PCRE2 10.47 in-tree. TLS cert: `sandbox/certs/`. docker TILTOTT. ngxlogs/ ~450MB untracked.
- **(S10) pinned geo-kulcs:** IPFire signing-key.pem (secp521r1, 2019-12-10 Michael Tremer); signing-key.pem SHA-256 `c9b397a24e93db4ff71044011d836d6b74b5432aa4076c80c8b6df9d8494ba41`; beagyazott PEM-blokk SHA-256 `7d927e19042d9cf12ef4644d2d4fd3095e26e9b5815ebd9e82d973219497430e`. Valodi `geodb/location.db` = 63,517,012 byte (2026-06-12); cap 512 MiB.

---

## 8. Open questions / threads

- **(S18 RESOLVED) Gap-loop iteracio 2 (config/IaC + appliance fingerprints)** — **KESZ (`cf244cb`).** A partner a 3 karbantartasi iranyt valasztotta; stale-fix NO-OP, scanners.list broad-ext config + 16 appliance fingerprint + Symfony + .php-broaden, generikus tail KIHAGYVA. B FP-gate PASS, C re-frozen 40,614, 9/9. **A KOVETKEZO (partner-dontes):** **honeypot D** az egyetlen erdemi strukturalt hatralek (ASN/geo a tamado IP-kbol, sajat geo-reader, no libloc; `reference/loctest.c` geo-OOB-ot fixelni) VAGY tovabbi alacsony-volumenu gap-loop (a fo jeloltek MAR BENT) VAGY uj feladat. **NE kezdj bele iranymutatas nelkul.**
- **(S18 NYITOTT, opcionalis) generikus szotar-tail** szandekosan kihagyva (Decision #89): `/login`, `/home`, `/admin`, `/test`, `*.shtml`, `*.jhtml` stb. Ha a partner ezeket is akarja (agressziv), kulon kor + C re-freeze.
- **(S17 RESOLVED) Gap-loop iteracio (2+3)** — **KESZ (`a1bda45`).** scanners.list+args.list bovites (gap-loop B6 fo jeloltek + §3.1 + misc secret-leaks), B FP-gate PASS, C re-frozen 38,905, 9/9. A KOVETKEZO (partner-dontes): **honeypot D** (ASN/geo a tamado IP-kbol, sajat geo-reader, no libloc; `reference/loctest.c` geo-OOB fixelni) VAGY **tovabbi gap-loop** (maradek: Symfony `/debug/default/view`, alacsony-volumenu uncatalogued tail; minden edit utan C re-freeze) VAGY **scanners.list tovabbi bovites**.
- **(S17 NYITOTT, opcionalis) maradek alacsony-volumenu jeloltek** amiket NEM vettem fel (borderline / kis volumen): Symfony `/debug/default/view`, `/hudson`, `/version`, `/webui`, `/containers/json` mar bent. Szolj ha kell.
- **(S16 RESOLVED) Honeypot C** — **KESZ (`2f0c18e`), bekommitolva.** A partner a "mind" (teljes covered halmaz) mellett dontott; enforce-modu fixture + harness leszallitva, 9/9 dim frozen-match. **A KOVETKEZO (uj context, partner-dontes): honeypot D** (ASN/geo a tamado IP-kbol, sajat geo-reader, no libloc; `reference/loctest.c` geo-OOB bugot hordoz -> fixelni) VAGY a **gap-loop** a B6 jeloltekbol VAGY scanners.list bovites.
- **(S16 NYITOTT, NEM-blokkolo) `docs/threat-model.md` §6.B meg "(planned)"-et ir**, pedig B leszallt `291621d`-ben (stale). Az introt frissitettem, de a §6.B torzset NEM (C scope-on kivul). Ha a partner akarja, kulon egysoros javitas.

- **(S7 RESOLVED) Build-recept:** a `cmake --build build --target waf_module` fast-target MUKODIK.
- **(S8/S9/S10/S11 RESOLVED) A teljes feature-roadmap (1-4) KESZ:** #1 args/cookie/referer (`3a48d61`), #2 CIDR fake-bot (`0638343`+`1e490d7`), #4 location.db verify (`24f9145`), **#3 rate-limit (`c426d98`).** Nincs tobb tervezett roadmap-feature.
- **(S12) Eles prod restart + `git push`: a PARTNER hataskore — KIVEVE a checkpoint teendoibol.** A prod le van allitva S5 ota; a HEAD `c426d98` origin/main elott 6 commit-tal (a sandbox kulccsal a push `Permission denied (publickey)`). Ne tervezz restartot/push-t; a partner intezi.
- **(S12 RESOLVED) sajat `sa`-feloldas (XFF / real-IP / mail Client-IP trust-hatar) audit** — kivizsgalva, a trust-modell MAR teljesen dokumentalt a README-ben (nincs doc-gap); konszolidalt tabla inline atadva, NEM doksiba (Decisions #65). Nincs tovabbi teendo.
- **(S15 RESOLVED) COMMIT-SCOPE:** a partner ugy dontott, hogy a kulso-pull `fixtures/` IS felmegy (a feed-ekkel egyutt) — minden forras permisszív licencű (CRS Apache-2.0 / SecLists MIT / FuzzDB / bad-bot-blocker / crawler-user-agents), attribucio a `docs/threat-intel-sources.md`-ben. Bekommitolva `291621d`-ben (Decision #77). Nincs tovabbi teendo.
- **(S13->S14 RESOLVED) Honeypot B IMPLEMENTACIO** — **KESZ (S14), partner elfogadta.** A kovetkezo: **C** (bounded fixture CI-ba; licensing tisztazando) + a **gap-loop** a B6 jeloltekbol (wlwmanifest / cgi-bin->/bin/sh / php://input args.list / Symfony / VPN; generikus `\.php` detect-FP-check utan). **D** kesobb: sajat geo-reader IP->ASN/CC (no libloc; `reference/loctest.c` ujrahasznosithato DE geo-OOB bugot hordoz, fixelni). Nyitott (kutatasbol): Cookie-injection + XFF-bypass ERTEK fixture-hoz nincs kesz gepi forras, kezzel.
- **F4 deployment-invarians:** az auth_http location bizonyithatoan internal-only (`waf off`, bind 127.0.0.1).

---

## 9. Risks & watch-outs

- **(S16) A regresszios fixture FROZEN — ha SZANDEKOSAN valtozik a lista-viselkedes** (uj scanner-pattern, action-valtas 404<->403<->444), a harness BUKIK, mert a fixture a regi verdiktet orzi. ILYENKOR a fixture-t UJRA kell freezelni (`freeze-regression-fixture.pl` futo regression-nginx ellen) es bekommitolni — a harness-bukas NEM mindig regresszio, lehet szandekos valtozas amihez a fixture-t frissiteni kell. (A negativ proba pont ezt a megkulonboztetest gyakorolja.)
- **(S16) `waf_reason_header on` GLOBALISAN a regression-confban** (enforce vhostokon is) — ez CSAK teszt-conf; a prod-invarians valtozatlan (default OFF, info-disclosure; lasd S14 risk). A regression-conf loopback-only, soha nem prod.
- **(S16) A `.freeze-tmp/` scratch gitignore-olt** — a freeze + harness ide ir (probe-kimenetek, subset-feed-ek, compare.pl, result-ok). NE commitold; reprodukalhato.
- **(S16) A negativ proba a `scanners.list`-et ideiglenesen modositja** — mindig allitsd vissza (a `(^|/)\.env` sort). Az S16-ban visszaallitva, a commitban NINCS benne; de jovobeli demo utan ellenorizd a `git status`-t.

- **(S12) AZ ELES PROD LE VAN ALLITVA (partner allitotta le S5-ben); a restart + `git push` a PARTNER hataskore — NE tervezz restartot/push-t, S12-ben kivettuk a teendokbol.** (Site example.com :443 nem szolgal; HEAD `c426d98` origin/main elott 6 commit-tal; a push a sandbox kulccsal `Permission denied (publickey)`.)
- **⚠️ FAIL-CLOSED DEFAULT:** `waf`/`waf_stream` direktiva nelkuli blokk ENFORCE-ol (off->enforce). Barmilyen conf-iras/teszt-conf eseten audit kell (kulonosen auth_http -> `waf off`).
- **(S10) A geo DB betolteskor kriptografiailag verifikalt (#4, fail-closed):** alairatlan / kezzel-szerkesztett / csonkolt DB -> `nginx -t` ELBUKIK, nginx nem indul (szandekos). A repoban levo `geodb/location.db` verifikal (bizonyitott); barmilyen sajat/uj DB-t a `reference/locverify.c` oracle-lel kell ellenorizni hasznalat elott.
- **`ngxlogs/` (~450MB) untracked** — partner kezeli, NE nyulj hozza, NE commitold.
- **(S14) `.cache/` untracked** — webfetch/curl cache, NE commitold (tedd `.gitignore`-ba a commit elott).
- **(S14) korpusz-derivatum commit (Decision #76):** a FEED-ek (`replay-vectors.jsonl` ~11MB, `replay-ua-vectors.jsonl` ~2.5MB, `replay-referer-vectors.jsonl`) felmehetnek — ez ~14MB derivatum a repoba (partner-jovahagyott; IP-mentes). A results/riportok NEM. A `fixtures/` (kulso-pull, ~800KB) licensing-fuggo, partner donti.
- **(S14) `waf_reason_header` info-disclosure:** a header a verdiktet (melyik szabaly fogott) felfedi — ezert default OFF; prod-conf-audit: SOHA ne legyen `waf_reason_header on` eles vhoston.
- **`reference/loctest.c` ugyanazt a geo-OOB bugot hordozza** (F1/F2) — ha valaha hasznaljuk (honeypot D), fixelni kell.
- **(S11) A rate-limit a `waf_rate_zone`-tol fugg:** HTTP-ben `waf_rate_limit` zona NELKUL -> `nginx -t` EMERG (szandekos). STREAM `waf_stream_rate_limit` zona nelkul -> CSENDBEN fail-open (no-op). Prod-conf-audit: ha rate-limitet akarsz a stream/mail fejen, a `waf_rate_zone`-t a `http{}`-ben KELL deklaralni. A zona reload-on megorzi a token-allapotot; ATMERETEZES (`size=`) full restartot igenyel (nginx shm size-conflict).
- **(S10) Kulcs-rotacio = modul-rebuild.** Az IPFire P-521 kulcs 2019 ota stabil (tobb-eves horizont), de ha rotalnak, a beagyazott PEM-et frissiteni kell a waf_geo.c-ben es ujraepiteni. A dual-sig EITHER-valid logika a rotaciot atmenetileg tamogatja, ha mindket kulcsot pinneljuk.
- **(S11) A #1+#2+#3+#4 mind backward-kompat:** #1/#2/#3 lista/direktiva nelkul inaktiv (a rate-limit csak `waf_rate_zone`+`waf_rate_limit` eseten el); #4 geo-verify a valodi alairt DB-n atmegy. A #3 uj `stat_shm_t` mezot (`http_resp_429`) + nagyobb `WAF_REASON_*` enumot hozott -> a stats shm sizeof valtozott (binaris csere friss szegmenst igenyel, counterek nullazodnak; HUP reload ugyanazzal a binarissal biztonsagos).
- **build-recept (CMake-fa) + OpenSSL-rebuild trap** valtozatlanul el. docker TILTOTT.

---

## 10. Next steps (ordered)

> `git push` = a PARTNER hataskore (Permission denied publickey; prod leallitva S5 ota). NE pusholj.

1. ~~**COMMIT**~~ → **(S15) KESZ** + ~~**Honeypot C**~~ → **(S16) KESZ** (`2f0c18e`) + ~~**Gap-loop iteracio (2+3)**~~ → **(S17) KESZ** (`a1bda45`) + ~~**Gap-loop iteracio 2 (config/IaC + appliance)**~~ → **(S18) KESZ** (`cf244cb`). Munkafa tiszta, HEAD origin/main (=`2f0c18e`) elott **2** commit (`a1bda45`+`cf244cb`). **PUSH a partnere** (Permission denied publickey; prod leallitva S5 ota).
2. **A KOVETKEZO: a partner friss contexttel DONT a tovabbiakrol.** Harom opcio (NE kezdj bele iranymutatas nelkul):
   - **Honeypot D** — ASN/geo tuning a tamado IP-kbol (`docs/threat-model.md` §6.D): a top external forrasokat (kiveve `10.0.0.0/24`) a sajat geo-readeren at CC+ASN-re feloldani (NO libloc / `location` CLI), majd persistent hostile /24-ek -> `waf_blocklist`, domináns ASN-ek -> `waf_asn_block`, orszagok -> `waf_geo_block` jeloltek. FIGYELEM: `reference/loctest.c` ugyanazt a geo-OOB bugot hordozza (F1/F2) -> hasznalat elott fixelni.
   - **Gap-loop** a B6 uncovered-jeloltekbol: dynamic-ext `\.php` 127k / wlwmanifest 13k / cgi-bin->/bin/sh 4.3k / php://input 2.1k / Symfony / VPN — a generikus `\.php` szabaly CSAK detect-FP-check (B) utan. Minden uj scanners.list-sor utan a **C harness** (`run-regression-tests.sh`) megfogja ha valamit elrontott, ES a fixture-t ujra kell freezelni az uj (helyes) verdiktekkel.
   - **scanners.list adatvezerelt bovites** (§3.1: nmap `Trinity`, `/dns-query` DoH, `/hello.world`).
3. **Ha a lista-viselkedes SZANDEKOSAN valtozik** (gap-loop / bovites): a regresszios fixture-t UJRA kell freezelni — indits regression-nginx-et (`waf-regression-test.conf`), futtasd `freeze-regression-fixture.pl`-t, ellenorizd a diff-et (uj/valtozott verdiktek varhatok-e), majd commitold a frissitett `regression-{vectors,headers}.jsonl`-t. A harness-bukas != mindig regresszio.
4. **A feature-roadmap (1-4) TELJES** — nincs tobb tervezett feature.
5. **(opcionalis/nyitva)** JA4 Wireshark/QUIC manualis validacio. (GREASE dedup SZANDEKOS — NE bantsd.) _(A `sa`-feloldas audit S12-ben LEZARVA — Decisions #65.)_

---

## 11. Activation prompt (paste into new session)

> Folytatjuk az edge-firewall nginx WAF modul munkajat (`/mnt/nvme/imaginarium/openresty`, git repo, branch `main`). A teljes session-kontextus a `.claude/tmp/checkpoint.md` fajlban van — olvasd el TELJESEN, mielott barmihez hozzanyulnal. **AZ S18-BAN A GAP-LOOP ITERACIO 2 LESZALLITVA + BEKOMMITOLVA:** `cf244cb` (UJ commit, NEM amend) — a partner a 3 karbantartasi iranyt valasztotta (stale-fix + tovabbi gap-loop + scanners.list bovites), honeypot D KIHAGYVA. Stale-fix = NO-OP (a §6.B mar S17-ben done). scanners.list bovites (mind 404): config/IaC/secret-leak BROAD-EXT (`\.ya?ml$`/`\.properties$`/`\.tfstate`/`\.tfvars$`, partner-dontes) + ~30 enumeralt .json/dotfile secret (blankett .json KIHAGYVA a /app.json baseline miatt) + Symfony `/debug/default/view` + generikus .php kiterjesztve (.phpN + `.php::$DATA`/`.php~`/`.php.old`) + bare `/phpinfo` + 16 appliance/VPN/RCE fingerprint (Citrix/Telerik/GPON/Cisco-CSCOL/SAP/D-Link/Pulse/F5/SonicWall/MobileIron/ColdFusion/Sitecore...). **Generikus szotar-tail KIHAGYVA** (partner: /login,/home,/admin... prodban legit lehet). B FP-gate PASS (uncatalogued 21.6->35.3%, appliance 100%, php 99.9%); C fixture re-frozen 38,905->40,614 ({404:40,573 403:146 444:55}, 403/444 byte-azonos); 9/9 frozen-match; unit 6/6 + stat 131/131 valtozatlan; NINCS .c valtozas (listak hot-reload); egy p:minion-runner vegezte a compile+B+freeze+C+unit+stat futtatast. Munkafa TISZTA, HEAD origin/main (=`2f0c18e`) elott **2** commit (`a1bda45`+`cf244cb`), **push a partnere** (Permission denied publickey, prod leallitva S5 ota — NE pusholj). A honeypot-program **A/B/C KESZ, D hatravan**; a feature-roadmap (1-4) TELJES. **A KOVETKEZO: a partner DONT** — a honeypot **D** (ASN/geo a tamado IP-kbol, sajat geo-reader, no libloc; `reference/loctest.c` geo-OOB-ot fixelni) az egyetlen erdemi strukturalt hatralek; a gap-loop fo jeloltei MAR BENT. NE kezdj bele iranymutatas nelkul — kerdezz. **Szabalyok:** mcp-git read-only + commit Bash-bol (staged path-ok, NE `-A`); fajl-edit `purity_call` (NEM built-in Edit); C-nav `clangd_call`; meglevo .c -> fast-target (p:minion-builder, NINCS reconfigure); uj .c -> reconfigure; minden lista-edit utan C re-freeze KELL (futo regression-nginx 283xx + `freeze-regression-fixture.pl`) + `run-regression-tests.sh`; ngxlogs/ read-only; NEM hasznalunk liblocot; docker TILTOTT; push = PARTNER. Ha barmi nem tiszta, kerdezz vissza, ne talalgass.
>
> _(Elozo S17 aktivalo prompt, megorizve:)_ **AZ S17-BEN A GAP-LOOP (2+3) LESZALLITVA + BEKOMMITOLVA:** `a1bda45` (amend) — scanners.list+args.list adatvezerelt bovites: generikus .php catch-all (php->99.2%, phpadmin->98.5%), wlwmanifest (wp->99.5%), /bin/sh, /remote/login, /+cscoe+/, Trinity, /hello.world, + credential/config/infra-leak cluster (uncatalogued 14.1->21.6%); args.list php://input 444. Akcio-flip: ~46 phpmyadmin/pma *.php most 404 (volt 403; scanner_lookup precedencia 404>403>444). B FP-gate PASS; C fixture re-frozen 21,263->38,905 ({404:38,864 403:146 444:55}); 9/9 dim 100% frozen-match; unit 6/6 + stat 131/131 valtozatlan; NINCS .c valtozas (listak hot-reload). Munkafa TISZTA, HEAD origin/main (=`2f0c18e`, az S16 9 commitja FELKERULT) elott **1** commit (`a1bda45`), **push a partnere** (Permission denied publickey, prod leallitva S5 ota — NE pusholj). A honeypot-program **A/B/C KESZ, D hatravan**; a feature-roadmap (1-4) TELJES. **A KOVETKEZO: a partner DONT a tovabbiakrol** — opciok: honeypot **D** (ASN/geo a tamado IP-kbol, sajat geo-reader, no libloc; `reference/loctest.c` geo-OOB-ot fixelni), **tovabbi gap-loop** (a fo B6-jeloltek MAR BENT az S17 ota; maradek: Symfony `/debug/default/view` + alacsony-volumenu uncatalogued tail; minden lista-edit utan a C harness fog + fixture-ujra-freeze KELL), vagy **scanners.list** tovabbi bovites. NE kezdj bele iranymutatas nelkul — kerdezz. **Szabalyok:** mcp-git read-only + commit Bash-bol (staged path-ok, NE `-A`); fajl-edit `purity_call` (NEM built-in Edit); C-nav `clangd_call`; meglevo .c -> fast-target (p:minion-builder, NINCS reconfigure); uj .c -> reconfigure; ngxlogs/ read-only; NEM hasznalunk liblocot; docker TILTOTT; **push = PARTNER**. Ha barmi nem tiszta, kerdezz vissza, ne talalgass.

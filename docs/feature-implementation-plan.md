# Feature Implementation Plan: A legacy forward-proxy tűzfal migrációja a heavybag WAF modulra

> Nyelv: a prózai szöveg magyar; a kód, az nginx direktívák és az útvonalak angolul (változatlan formában) szerepelnek.

## 1. Requirements Summary

### Context (a probléma és a cél)

A `v/nginx-forward-proxy/` fában jelenleg **három, kézzel karbantartott védelmi réteg** él egymás mellett:

1. **Path-blacklist** — `nginx-firewall.conf` (~122 sor): exact-path `location` blokkok ismert scanner-útvonalakra (`/administrator`, `/actuator`, `/geoserver`, `/pEWP`, `/owa`, `/ecp`, `/autodiscover` stb.), plusz túl tág `~*` regex `location`-ök (`~* html`, `~* .php`, `~* /admin`, `~* /main`, `~* /home`), plusz `if ($http_user_agent = "")` és `if ($host = "203.0.113.10")` blokkok. Ez minden HTTPS vhost-ba `include`-olva van (`example-https.conf:23`, `parastable.conf:22`, `example-www-test.conf:24`, `example-adm-test.conf:24`).
2. **Geo + rate machinery** — a `nginx-forward-proxy.conf` http{} blokkjában: `geo $is_hungary` (`nginx-forward-proxy.conf:27-30`), két `map` (`:33-41`), két `limit_req_zone` (`zone=foreign rate=5r/s`, `zone=hungarian rate=30r/s`, `:43-44`). A `parastable.conf` per-location `limit_req`/`limit_req_status` (`:36-38, 66-68, 96-98`) és HU-only `if ($is_hungary = 0) return 404` (`:32-34, 62-64, 92-94`) sorokon keresztül használja ezeket.
3. Mindezt kézzel kell bővíteni minden új scanner-mintánál.

A **cél**: ezt a három réteget a repó saját **heavybag WAF moduljának** natív direktíváival kiváltani, központosítva, `detect` módban előkészítve, hogy a forgalom megfigyelhető legyen az éles (`enforce`) átkapcsolás előtt.

**Kulcs-megállapítás (verifikált):** a legacy path-lista lefedettsége MÁR migrálva van. A `modules/ngx_http_heavybag/lists/scanners.list` (a `# ---- noisy junk paths from the legacy list` szekcióban, `scanners.list:168`-tól) horgonyzott (`^/...$`) formában tartalmazza a teljes legacy path-listát: `^/administrator` (`:157`), `^/actuator` (`:80`), `^/geoserver` (`:81`), `^/owa` (`:64`), `^/ecp` (`:65`), `^/autodiscover` (`:66`), `^/pEWP$` (`:183`) stb. A túl tág legacy regexeket (`~* /main`, `~* /home`) **szándékosan elhagytuk** (false-positive kockázat — lásd `scanners.list:8` kommentet). Ezért **ez a feladat konfigurációs átírás, nem új listatartalom létrehozása.**

### Functional Requirements

- [FR-1] Az `nginx-forward-proxy.conf` töltse be a heavybag modult és kapcsolja be a WAF-ot `detect` módban (Phase 1), a meglévő geo/map/limit_req gépezet mellett, védelmi rés nélkül.
- [FR-2] A WAF fedje le a scanner-path szűrést (`waf_scanner_list`), az üres/scanner UA blokkolást (`waf_bot_block on`), a geo-szűrést (`waf_geo_db` + `waf_geo_whitelist HU` a HU-only vhost-okhoz) és a rate-limitet (`waf_rate_zone` + `waf_rate_limit` `for_geo=HU` differenciálással).
- [FR-3] A `detect` ablak alatt a WAF csak megfigyel (200-at ad, `would_block` számlálót növel, beállítja `$waf_reason`-t); a `$waf_reason $waf_type $waf_country` kerüljön be az access.log formátumába.
- [FR-4] Cutover (Phase 2): `waf detect;` → `waf on;`, a legacy `geo`/`map`/`limit_req_zone` blokkok törlése, a vhost-okból az `include nginx-firewall.conf;` és az `if ($http_user_agent = "")` eltávolítása, a `parastable.conf` `if ($is_hungary = 0)` → `waf_geo_whitelist HU;` csere, a per-location `limit_req` törlése.
- [FR-5] Egy teljesen kommentált, **inert** `heavybag-stream-mail.conf` template leszállítása (stream{} + mail{}/auth_http scaffold), amely NINCS includolva a fő configba — jövőbeli kapacitás, nem meglévő forgalom migrációja.

### Non-Functional Requirements

- [NFR-1] **Nulla védelmi rés**: Phase 1 additív — a régi tűzfal és rate-limit aktív marad, amíg a WAF csak megfigyel.
- [NFR-2] **Nincs C-kód módosítás**: kizárólag konfiguráció a `v/nginx-forward-proxy/` fában.
- [NFR-3] **ABI-kompatibilitás**: a `load_module`-lal betöltött `.so` csak ABI-azonos nginx-be tölthető (lásd Prerequisite).
- [NFR-4] **Nincs info-disclosure éles enforce-ban**: `waf_reason_header` csak a detect-ablakban legyen `on`, cutover-kor `off`.

### Success Criteria

- [SC-1] `nginx -t` zöld a 1.31.2 binárissal mindkét fázisban (Phase 1 config és a cutover diff alkalmazása után).
- [SC-2] A detect-ablakban valós felhasználók `waf=none` reason-nel logolódnak (false-positive ellenőrzés).
- [SC-3] Cutover után a smoke-tesztek átmennek: `/.git/config` → 404 (`scanner_path`), üres UA → 404 (`empty_ua`), nem-HU `/parastable` → 404 (`geo_whitelist`), legitim kérés → 200, küszöb feletti terhelés → 429 (`rate_limit`).
- [SC-4] A `203.0.113.10` direct-IP blokk és a `/send-message`+`/health-check` 404 location-ök változatlanul megmaradnak.

### Assumptions

- A `/opt/imaginarium/conf/heavybag/` deploy-útvonal a célgépen létrehozható és a deploy-folyamat oda másolja a `.so`-t, a `lists/`-et és a `geodb/`-t.
- A célgépen futó nginx ABI-azonos a `sandbox/sbin/nginx` (nginx/1.31.2) buildjével.

### Out of Scope

- A `nginx-1.19.9.1.conf` (legacy standalone snapshot) — **ÉRINTETLEN marad**, nem az éles config.
- A `/send-message` + `/health-check` 404 location-ök és az `if ($host = "203.0.113.10")` blokk — host/path app-szabályok, NEM reputáció, a WAF-ba NEM kerülnek át (USER DECISION #4).
- A heavybag modul C forráskódjának bármely módosítása.
- Éles L4/SMTP forgalom migrációja — nincs ilyen forgalom; a stream/mail csak inert template.

## 2. Architecture Analysis

### Affected Subsystems

- **Forward-proxy main config** — `v/nginx-forward-proxy/nginx-forward-proxy.conf` — itt töltődik be a modul és kerül a http{}-szintű WAF konfiguráció; a legacy geo/map/limit_req innen tűnik el cutover-kor.
- **HTTPS vhost-ok** — `vhosts.d/example-https.conf`, `parastable.conf`, `example-www-test.conf`, `example-adm-test.conf` — cutover-kor innen tűnik el a firewall-include és az üres-UA `if`; a `parastable.conf` HU-only logikája `waf_geo_whitelist`-re vált.
- **Legacy firewall fragment** — `vhosts.d/`-n kívül `nginx-firewall.conf` — cutover-kor törlés/`.bak`.
- **Heavybag modul (read-only)** — `modules/ngx_http_heavybag/` — a direktíva-felület és a `lists/`+`geodb/` adatforrás; NEM módosul.

### Integration Points

- **load_module** (config top, http{}/stream{} blokkon kívül) → a `.so` betölti mind a HTTP, mind a STREAM heavybag modult (egy `.so` két modult tartalmaz).
- **http{} PREACCESS fázis** → a WAF itt hozza a verdiktet (`detect` = megfigyel, `enforce` = blokkol); az `$waf_*` változók a NOCACHEABLE módon a log-ba és add_header-be kerülhetnek.
- **waf_rate_zone (http{} MAIN CONF)** → egy process-szintű shm zóna, amelyet a `waf_rate_limit` (HTTP) és a `waf_stream_rate_limit` (stream) is használ — ezért a stream rate-limit a http{}-ben deklarált zónától függ.
- **geodb/location.db** → a `waf_geo_db` által betöltött IPFire location DB; a `$waf_country`/`$waf_asn` forrása, kiváltja a `geo $is_hungary` + `ip-list-hu.txt`-t.

### Constraints

- **ABI-kötöttség**: a `.so` a `sandbox/sbin/nginx` (nginx/1.31.2, `--with-http_v3 --with-stream --with-mail --with-http_ssl --add-dynamic-module=.../ngx_http_heavybag`) buildhez kötött. A vhost-ok már `http3 on; listen 443 quic;`-et használnak (`example-https.conf:4,8`), amit csak ez az 1.31.2 build támogat → a bináris deploy konzisztens, nem extra teher.
- **waf_rate_zone elhelyezés**: KIZÁRÓLAG http{} MAIN CONF, és bármely `waf_rate_limit` ELŐTT kell állnia (`ngx_http_heavybag_module.c:423` — `NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1`, `NGX_HTTP_MAIN_CONF_OFFSET`).
- **`return` a REWRITE fázisban fut, a WAF PREACCESS előtt** → egy `location`, ahol csak `return`/`proxy_pass` van és WAF-verdiktet várunk, content-fázisú handlert (nem `return`-t) igényelhet (lásd `sandbox/nginx.conf:50-54` kommentet a geo_whitelist demónál). A `parastable.conf` `location`-jei `proxy_pass`-olnak, így a PREACCESS verdikt rendben lefut.

## 3. Captured Information

### Existing Patterns (verifikált, file:line referenciával)

**WAF mód enum** (`ngx_http_heavybag_module.c:94`):
```c
static ngx_conf_enum_t  ngx_http_heavybag_mode[] = {
    { ngx_string("off"),     HEAVYBAG_MODE_OFF     },
    { ngx_string("detect"),  HEAVYBAG_MODE_DETECT  },
    { ngx_string("enforce"), HEAVYBAG_MODE_ENFORCE },
    { ngx_string("on"),      HEAVYBAG_MODE_ENFORCE },   /* on == enforce */
};
```
A `waf` deklarálatlanul ENFORCE-ra/fail-closed-ra esik (a merge ezt érvényesíti), ezért Phase 1-ben explicit `waf detect;` kell minden szinten, ahol megfigyelni akarunk.

**Production-style http{} idióma** (`sandbox/nginx.conf:14-29`) — ez a Phase 1 sablon mintája:
```nginx
waf               on;          # Phase 1-ben: detect
waf_bot_block     on;
waf_scanner_list  .../lists/scanners.list;
waf_scanner_ua_list  .../lists/scanner-ua.list;
waf_ai_crawler_list  .../lists/ai-crawler.list;
waf_crawler_list     .../lists/crawler.list;
waf_bot_list         .../lists/bot.list;
waf_geo_db        .../geodb/location.db;
waf_geo_block     CN RU;       # forward-proxynál NEM kell; whitelist HU jön a vhost-ban
waf_trusted_proxy 127.0.0.1;
```

**Rate-limit szabályválasztás** (`heavybag_rate.c:381` — „first for_geo match wins", `:456` — `for_geo=` parse): az első `for_geo` szabály nyer, amelynek CC-listája tartalmazza a verdikt-országot (ha geo-lookup tényleg lefutott); egyébként a `for_geo` nélküli default szabály. A `waf_rate_limit` igényli a korábban deklarált `waf_rate_zone`-t (`ngx_http_heavybag_module.c:2134` komment).

**geo_whitelist felülírja a geo_block-ot**: csak a listázott országok mennek át, a többi 404 (`heavybag_stream.c:576` komment a stream oldalon; a HTTP oldali `waf_geo_whitelist` ugyanígy `NGX_CONF_1MORE`, `ngx_http_heavybag_module.c:365`).

**mail auth_http idióma** (`sandbox/nginx.conf:60-78`): az auth_http endpoint dedikált localhost server-en, **`waf off;`**-fal (hogy a HTTP PREACCESS handler ne pre-emptelje a content handlert a loopback peeren); a content handler a `Client-IP` request headert ellenőrzi.

### Type Definitions / Direktíva-felület (verifikált a C command table-ből)

HTTP command table — `ngx_http_heavybag_module.c:191-448`:

| Direktíva | Kontextus | Args | Forrássor |
|---|---|---|---|
| `waf off\|detect\|enforce\|on` | main/srv/loc | TAKE1 enum | `:193` |
| `waf_bot_block on\|off` | main/srv/loc | FLAG | `:200` |
| `waf_scanner_list <path>` | main/srv/loc | TAKE1 | `:246` |
| `waf_scanner_ua_list <path>` | main/srv/loc | TAKE1 | `:254` |
| `waf_ai_crawler_list <path>` | main/srv/loc | TAKE1 | `:261` |
| `waf_crawler_list <path>` | main/srv/loc | TAKE1 | `:268` |
| `waf_bot_list <path>` | main/srv/loc | TAKE1 | `:275` |
| `waf_args_list <path>` | main/srv/loc | TAKE1 | `:293` |
| `waf_cookie_list <path>` | main/srv/loc | TAKE1 | `:300` |
| `waf_referer_list <path>` | main/srv/loc | TAKE1 | `:307` |
| `waf_reason_header on\|off` | main/srv/loc | FLAG | `:323` |
| `waf_geo_db <path>` | main/srv/loc | TAKE1 | `:330` |
| `waf_geo_block CC...` | main/srv/loc | 1MORE | `:337` |
| `waf_asn_block ...` | main/srv/loc | 1MORE | `:344` |
| `waf_geo_whitelist CC...` | main/srv/loc | 1MORE | `:365` |
| `waf_flag_block ...` | main/srv/loc | 1MORE | `:372` |
| `waf_trusted_proxy <cidr>` | main/srv/loc | TAKE1 | `:379` |
| `waf_blocklist <cidr>` | main/srv/loc | TAKE1 | `:386` |
| `waf_allowlist <cidr>` | main/srv/loc | TAKE1 | `:393` |
| `waf_mail_auth` | **loc only** | NOARGS | `:400` |
| `waf_mail_backend <ip> <port>` | main/srv/loc | TAKE2 | `:407` |
| `waf_status` | **loc only** | NOARGS | `:414` |
| `waf_rate_zone size=<size>` | **main only** | TAKE1 | `:423` |
| `waf_rate_limit rate=... [burst=N] [for_geo=CC,...]` | main/srv/loc | 1MORE | `:430` |
| `waf_ja4_list <path>` | main/srv/loc | TAKE1 | `:440` |

STREAM command table — `heavybag_stream.c:114-180` (stream{} kontextus): `waf_stream off\|detect\|enforce\|on` (`:116`), `waf_geo_db` (`:123`), `waf_geo_block` (`:130`), `waf_asn_block` (`:137`), `waf_geo_whitelist` (`:144`), `waf_flag_block` (`:151`), `waf_blocklist` (`:158`), `waf_allowlist` (`:165`), `waf_stream_rate_limit ...` (`:172`). A stream mód enum (`heavybag_stream.c:77`) azonos a HTTP-vel.

**`$waf_reason` értékek** (verifikált, `ngx_http_heavybag_module.c:72-83` környékén): `none`, `allowlist`, `blocklist`, `geo`, `geo_whitelist`, `flag`, `scanner_ua`, `empty_ua`, `scanner_path`, `asn`, `method`, `args`, `cookie`, `referer`, `fake_bot`, `rate_limit`, `spoof`. Az összes `$waf_*` változó NOCACHEABLE és `waf off` mellett is működik.

### Build System / Artifacts (verifikált)

- Modul `.so`: `sandbox/modules/ngx_http_heavybag_module.so` (mellette `*.so.old`).
- Listák: `modules/ngx_http_heavybag/lists/` — `scanners.list`, `scanner-ua.list`, `ai-crawler.list`, `crawler.list`, `bot.list`, `args.list`, `cookie.list`, `referer.list`, `ja4.list`, `verified-crawler.list`, `verified-crawler-local.list` (11 fájl, mind jelen van).
- Geo DB: `geodb/location.db` (mellette `location.db.xz`).
- Bináris: `sandbox/sbin/nginx` = nginx/1.31.2 (E), a `.so` ehhez ABI-kötött.
- Referencia idiómák: `sandbox/nginx.conf` (production-style, http{}+stream{}+mail{} demo), `modules/ngx_http_heavybag/tests/heavybag-stat-test.conf` (teljes feature-exerciser: `waf_rate_zone`/`waf_rate_limit`/`waf_geo_whitelist`/`waf_mail_auth`).

## 4. Alternative Approaches

### Selected: Two-phase, additive rollout (`detect` first, majd `enforce` cutover)

**Rationale**: A `detect` mód NEM blokkol — csak `would_block`-ot számol és `$waf_reason`-t állít. Ezért ha egy lépésben távolítanánk el a régi tűzfalat ÉS állítanánk `detect`-re, védelmi rés nyílna (scanner-ek elérnék a backendet, a rate-limit eltűnne). Az additív, kétfázisú megközelítés nullára csökkenti ezt a rést: Phase 1-ben a régi védelmi rétegek aktívak maradnak, a WAF csak megfigyel; a cutover csak akkor jön, ha a detect-logok tiszták.

**Trade-offs**: Két deploy-lépés és egy megfigyelési ablak árán nyerünk biztonságot; a HU IP-halmaz finoman változik (`ip-list-hu.txt` → location.db `country=HU`), de ez a detect-ablakban `$waf_country` segítségével megfigyelhető.

### Rejected: Big-bang csere (egy lépésben enforce + régi szabályok törlése)

**Reason**: A `detect`/`enforce` átállás és a régi szabályok eltávolítása közötti bármilyen sorrend rést nyit vagy false-positive-ot kockáztat megfigyelési ablak nélkül. A HU IP-set delta vakon, élesben jelentkezne.

### Rejected: Csak részleges migráció (pl. csak path-blacklist, geo/rate marad legacy)

**Reason**: A USER DECISION #1 FULL scope-ot ír elő (HTTP firewall + geo/rate → WAF, plusz stream/mail scaffold). A geo/rate legacy-ben hagyása fenntartaná a kézi karbantartást és a kettős konfigurációs felületet.

## 5. Implementation Strategy

### Overview

Phase 1: a `nginx-forward-proxy.conf`-ba additívan bekerül a `load_module` és a teljes http{}-szintű WAF konfiguráció `detect` módban, a meglévő geo/map/limit_req mellett. A WAF megfigyel és logol. Phase 2 (cutover): `detect` → `on`, a legacy gépezet törlése, a vhost-include-ok és üres-UA `if`-ek eltávolítása, a `parastable.conf` HU-logikájának `waf_geo_whitelist`-re cserélése. Külön, inert `heavybag-stream-mail.conf` template a jövőbeli L4/SMTP kapacitáshoz.

### Key Design Decisions

- **`detect` minden szinten Phase 1-ben**: mivel a deklarálatlan `waf` ENFORCE-ra esik, explicit `waf detect;` kell a http{}-ben (öröklődik a server/location szintekre).
- **`waf_geo_whitelist HU` a `geo $is_hungary` + `if` helyett**: a whitelist felülírja a geo_block-ot; a HU-only vhost-okban (`parastable.conf`) ez pontosan a legacy `if ($is_hungary = 0) return 404` szemantikája.
- **`waf_rate_limit ... for_geo=HU` + default szabály**: az első `for_geo` match nyer → HU forgalom 30r/s, minden más (default, `for_geo` nélkül) 5r/s — a legacy `zone=hungarian` / `zone=foreign` differenciálás natív megfelelője.
- **`waf_reason_header on` CSAK detect-ablakban**: a cutover-kor `off` (info-disclosure megelőzése).
- **stream/mail inert template**: nincs include-olva, amíg valós backend nincs.

### Risk Mitigation

- **ABI-mismatch** → Prerequisite-ként rögzítjük: a célgép nginx-e ABI-azonos a 1.31.2 build-del; a `load_module` egyébként hibázik a `nginx -t`-nél (azonnal kiderül).
- **HU IP-set delta** → a detect-ablakban `$waf_country` logolásával megfigyelhető, mielőtt élesedik.
- **`return` a PREACCESS előtt fut** → a `parastable.conf` `location`-jei `proxy_pass`-olnak, a verdikt rendben lefut; a stub_status és redirect szerverek nem WAF-célok.
- **`waf_rate_zone` sorrend** → mindig a `waf_rate_limit` előtt, http{} main-szinten.

## 6. Step-by-Step Plan

### Step 1: Prerequisite — ABI és deploy-layout ellenőrzése
**Files**: nincs config-módosítás; ellenőrzési lépés.
**Dependencies**: none
**Description**: Igazold, hogy a célgépen futó nginx ABI-azonos a `sandbox/sbin/nginx` (nginx/1.31.2, `--with-http_v3 --with-stream --with-mail --with-http_ssl --add-dynamic-module=.../ngx_http_heavybag`) build-del. Készítsd elő a deploy-layoutot (lásd Step 2). A `.so` forrása: `sandbox/modules/ngx_http_heavybag_module.so`; a listák: `modules/ngx_http_heavybag/lists/*.list`; a geo DB: `geodb/location.db`.
**Pattern to follow**: Captured Information → Build System.
**Verification**: a célgép `nginx -V` kimenete tartalmazza a fenti configure-argokat és a `1.31.2` verziót.

### Step 2: Deploy-artifaktumok másolása a `/opt/imaginarium/conf/heavybag/` alá
**Files**: deploy-folyamat (nem repo-config); létrehozandó cél-fa:
```
/opt/imaginarium/conf/heavybag/
├── ngx_http_heavybag_module.so      # forrás: sandbox/modules/ngx_http_heavybag_module.so
├── lists/                            # forrás: modules/ngx_http_heavybag/lists/*.list
│   ├── scanners.list
│   ├── scanner-ua.list
│   ├── ai-crawler.list
│   ├── crawler.list
│   ├── bot.list
│   ├── args.list
│   ├── cookie.list
│   ├── referer.list
│   └── ja4.list
└── geodb/
    └── location.db                   # forrás: geodb/location.db (~63MB)
```
**Dependencies**: Step 1
**Description**: Az artifaktumok másolása a célgépre. A repó-relatív útvonalak (`sandbox/...`, `modules/...`, `geodb/...`) csak a build-forrást jelölik; az éles config a `/opt/imaginarium/conf/heavybag/` abszolút útvonalakra mutat.
**Verification**: a fenti fa létezik, a `.so` és a `location.db` mérete a forrásnak megfelelő.

### Step 3 (PHASE 1): `nginx-forward-proxy.conf` — modulbetöltés és http{}-szintű WAF `detect` módban (additív)
**Files**: `v/nginx-forward-proxy/nginx-forward-proxy.conf` (modify)
**Dependencies**: Step 2
**Description**: A config tetejére (http{} blokkon KÍVÜL, a `pcre_jit on;` előtt vagy a `pid` után) kerüljön:
```nginx
load_module /opt/imaginarium/conf/heavybag/ngx_http_heavybag_module.so;
```
A http{} blokkba, a meglévő `geo $is_hungary` / `map` / `limit_req_zone` blokkok mellé (azok eltávolítása NÉLKÜL), kerüljön:
```nginx
    # --- heavybag WAF (Phase 1: detect, additive, zero gap) ----------
    waf                 detect;
    waf_bot_block       on;
    waf_reason_header   on;            # CSAK a detect-ablakra; cutover-kor off
    waf_trusted_proxy   127.0.0.1;

    waf_scanner_list     /opt/imaginarium/conf/heavybag/lists/scanners.list;
    waf_scanner_ua_list  /opt/imaginarium/conf/heavybag/lists/scanner-ua.list;
    waf_ai_crawler_list  /opt/imaginarium/conf/heavybag/lists/ai-crawler.list;
    waf_crawler_list     /opt/imaginarium/conf/heavybag/lists/crawler.list;
    waf_bot_list         /opt/imaginarium/conf/heavybag/lists/bot.list;
    waf_args_list        /opt/imaginarium/conf/heavybag/lists/args.list;
    waf_cookie_list      /opt/imaginarium/conf/heavybag/lists/cookie.list;
    waf_referer_list     /opt/imaginarium/conf/heavybag/lists/referer.list;
    waf_ja4_list         /opt/imaginarium/conf/heavybag/lists/ja4.list;

    waf_geo_db          /opt/imaginarium/conf/heavybag/geodb/location.db;

    # waf_rate_zone MUST precede any waf_rate_limit (main conf only)
    waf_rate_zone       size=10m;
    waf_rate_limit      rate=30r/s burst=50 for_geo=HU;   # HU
    waf_rate_limit      rate=5r/s  burst=10;              # default (foreign)
```
Megfigyelési log-format kiegészítés (a meglévő `access_log /opt/.../access.log;` `:56` előtt definiálva, majd a sor frissítve a formátum-névvel):
```nginx
    log_format heavybag_obs '$remote_addr - $remote_user [$time_local] "$request" '
                            '$status $body_bytes_sent "$http_referer" '
                            '"$http_user_agent" waf=$waf_reason type=$waf_type cc=$waf_country';
    access_log /opt/imaginarium/dataset/log/nginx/access.log heavybag_obs;
```
**Net effect**: a régi tűzfal + régi rate-limit AKTÍV marad (nulla rés); a WAF megfigyel és logolja, mit blokkolna.
**Pattern to follow**: `sandbox/nginx.conf:14-29` (production http{} idióma); rate-szabályválasztás `heavybag_rate.c:381`.
**Verification**: `nginx -t` zöld (lásd Step 8); a config a meglévő `geo`/`map`/`limit_req_zone` (`:27-44`) blokkokat ÉRINTETLENÜL hagyja; a vhost-include-ok (`:95-99`) változatlanok.

### Step 4 (PHASE 1 → megfigyelés): detect-ablak log-elemzés
**Files**: nincs config-módosítás.
**Dependencies**: Step 3 (deploy + reload)
**Description**: Néhány napon át figyeld az access.log `waf=` mezőjét. Ellenőrizd, hogy valós felhasználók `waf=none`-nal logolódnak (false-positive ellenőrzés), és hogy a `waf=scanner_path`/`empty_ua`/`rate_limit`/`geo_whitelist` találatok a vártak. Külön figyeld a `cc=` (`$waf_country`) mezőt a HU IP-set delta felméréséhez (`ip-list-hu.txt` vs. location.db `HU`).
**Pattern to follow**: `$waf_reason` értékkészlet (Captured Information).
**Verification**: tiszta detect-logok (nincs false-positive valós forgalmon) — ez a cutover gate-je (SC-2).

### Step 5 (PHASE 2 cutover): `nginx-forward-proxy.conf` — enforce-ra váltás és legacy gépezet törlése
**Files**: `v/nginx-forward-proxy/nginx-forward-proxy.conf` (modify)
**Dependencies**: Step 4 (tiszta detect-ablak)
**Description**: Pontos diff:
- `waf detect;` → `waf on;`
- `waf_reason_header on;` → `off` (vagy a sor törlése).
- Töröld a `geo $is_hungary { ... }` blokkot (`:27-30`).
- Töröld a két `map $is_hungary $limit_foreign/$limit_hu` blokkot (`:33-41`).
- Töröld a két `limit_req_zone` sort (`:43-44`).
A `waf_geo_db` + `waf_rate_limit` váltja ki ezeket. A log-format maradhat (vagy a `waf=`/`cc=` mezők megtarthatók diagnosztikára).
**Pattern to follow**: a Step 3-beli WAF blokk marad, csak a mód vált.
**Verification**: `nginx -t` zöld; a config nem hivatkozik többé `$is_hungary`-re, `$limit_foreign`-re, `$limit_hu`-ra, `zone=foreign`-ra, `zone=hungarian`-ra.

### Step 6 (PHASE 2 cutover): HTTPS vhost-ok — firewall-include és üres-UA `if` eltávolítása
**Files**: `vhosts.d/example-https.conf` (modify), `vhosts.d/example-www-test.conf` (modify), `vhosts.d/example-adm-test.conf` (modify), `vhosts.d/parastable.conf` (modify)
**Dependencies**: Step 5
**Description**: Mind a négy HTTPS vhost-ban:
- Töröld az `include nginx-firewall.conf;` sort (`example-https.conf:23`, `parastable.conf:22`, `example-www-test.conf:24`, `example-adm-test.conf:24`) — a scanner-path fedettséget a http{}-szintű `waf_scanner_list` adja.
- Töröld az `if ($http_user_agent = "") { return 404 " "; }` sort (`example-https.conf:25`, `parastable.conf:24`, `example-www-test.conf:26`, `example-adm-test.conf:28`) — lefedi a `waf_bot_block` → `empty_ua`.
- **TARTSD MEG** az `if ($host = "203.0.113.10") { return 404 " "; }` sort (USER DECISION #4) minden vhost-ban (`example-https.conf:27` stb.).
- A `example-https.conf`-ban a `/send-message`/`/health-check` location-ök a `nginx-firewall.conf:5-6`-ban élnek; mivel a firewall-include törlésre kerül, ezeket — ha továbbra is kellenek host/path app-szabályként — explicit `location` blokként át kell emelni a vhost-ba (USER DECISION #4: ezek megmaradnak, NEM kerülnek a WAF-ba). [Megjegyzés: a deploy-csapat döntse el, hogy a `/send-message`+`/health-check` app-szabályok hova kerüljenek; ezek nem reputációs szabályok.]
**Pattern to follow**: `waf_bot_block` → `empty_ua` reason (Captured Information).
**Verification**: `nginx -t` zöld; a négy vhost nem `include`-olja a `nginx-firewall.conf`-ot; a `203.0.113.10` blokk minden vhost-ban jelen.

### Step 7 (PHASE 2 cutover): `parastable.conf` — HU-only és per-location rate-limit cseréje
**Files**: `vhosts.d/parastable.conf` (modify)
**Dependencies**: Step 5
**Description**:
- A három `location` (`/parastable` `:31`, `/parastable/token` `:61`, `/parastable/ws` `:91`) mindegyikében:
  - Cseréld az `if ($is_hungary = 0) { return 404 " "; }` blokkot (`:32-34`, `:62-64`, `:92-94`) erre:
    ```nginx
    waf_geo_whitelist HU;
    ```
  - Töröld a per-location rate-limit hármast: `limit_req zone=foreign ...; limit_req zone=hungarian ...; limit_req_status 429;` (`:36-38`, `:66-68`, `:96-98`) — a rate-limit most a http{}-szintű `waf_rate_limit`-ből öröklődik.
  - **TARTSD MEG** az `auth_basic` + `auth_basic_user_file` és az összes `proxy_*` / `add_header` sort.
**Pattern to follow**: `waf_geo_whitelist` felülírja a geo_block-ot (`ngx_http_heavybag_module.c:365`); a `proxy_pass` `location` content-fázisa garantálja, hogy a PREACCESS WAF-verdikt lefut (Architecture → Constraints).
**Verification**: `nginx -t` zöld; a `parastable.conf` nem hivatkozik `$is_hungary`-re és nincs benne `limit_req`; mindhárom location-ban ott a `waf_geo_whitelist HU;` és megmaradt az `auth_basic`.

### Step 8 (PHASE 2 cutover): `nginx-firewall.conf` nyugdíjazása
**Files**: `v/nginx-forward-proxy/nginx-firewall.conf` (delete vagy `.bak`)
**Dependencies**: Step 6, Step 7 (semmi sem include-olja már)
**Description**: Miután egyetlen vhost sem `include`-olja, töröld a `nginx-firewall.conf`-ot, vagy nevezd át `nginx-firewall.conf.bak`-ra archiválásként. A `nginx-1.19.9.1.conf` ÉRINTETLEN marad.
**Pattern to follow**: Kulcs-megállapítás — a scanner-fedettség a `scanners.list`-ben él.
**Verification**: `nginx -t` zöld a fájl nélkül; a teljes fában nincs `include nginx-firewall.conf;` hivatkozás.

### Step 9: Inert stream/mail scaffold template leszállítása
**Files**: `v/nginx-forward-proxy/heavybag-stream-mail.conf` (create — NEM included)
**Dependencies**: Step 2 (a direktíva-felület ismert)
**Description**: Hozz létre egy teljesen kommentált, **inert** template-et a `sandbox/nginx.conf:86-133` mintájára. Tartalom (kommentekkel, hogy ez jövőbeli kapacitás, nem meglévő forgalom):
- `stream { waf_geo_db ...; waf_flag_block ...; server { listen <port>; waf_stream detect; waf_blocklist ...; waf_stream_rate_limit rate=... ; proxy_pass ...; } }` — a `waf_stream_rate_limit` a http{} `waf_rate_zone`-ját használja (`heavybag_stream.c:172`, `heavybag_stream.c:261` komment).
- `mail { auth_http 127.0.0.1:<port>/waf-mail-auth; ... server { protocol smtp; ... } }` plusz egy dedikált HTTP server `waf off;`-fal és `location = /waf-mail-auth { waf_mail_auth; waf_mail_backend <ip> <port>; }` (`sandbox/nginx.conf:60-78` minta).
A fájl tetején nagy kommentblokk: „INERT TEMPLATE — NOT included by nginx-forward-proxy.conf. There is no live L4/SMTP traffic in this deployment; all upstreams are HTTP. Activate only when a real backend exists."
**Pattern to follow**: `sandbox/nginx.conf:60-133` (stream{}+mail{}+auth_http demo).
**Verification**: a fájl létezik, NINCS `include heavybag-stream-mail.conf;` a `nginx-forward-proxy.conf`-ban; `nginx -t` változatlanul zöld (a template nem aktív).

## 7. Critical Files

| File | Role | Action |
|---|---|---|
| `v/nginx-forward-proxy/nginx-forward-proxy.conf` | éles fő config; itt töltődik a modul + http{} WAF | modify (Phase 1 + cutover) |
| `v/nginx-forward-proxy/nginx-firewall.conf` | legacy path-blacklist fragment | delete / `.bak` (cutover) |
| `v/nginx-forward-proxy/vhosts.d/example-https.conf` | fő HTTPS vhost | modify (cutover: include + üres-UA if törlés) |
| `v/nginx-forward-proxy/vhosts.d/parastable.conf` | HU-only Streamlit vhost | modify (cutover: geo_whitelist + rate-limit csere) |
| `v/nginx-forward-proxy/vhosts.d/example-www-test.conf` | teszt vhost | modify (cutover: include + üres-UA if törlés) |
| `v/nginx-forward-proxy/vhosts.d/example-adm-test.conf` | teszt vhost | modify (cutover: include + üres-UA if törlés) |
| `v/nginx-forward-proxy/heavybag-stream-mail.conf` | inert stream/mail scaffold | create (NEM included) |
| `v/nginx-forward-proxy/nginx-1.19.9.1.conf` | legacy standalone snapshot | **untouched** |
| `v/nginx-forward-proxy/vhosts.d/example-http.conf` | port 80 → 301 redirect, nincs firewall | **untouched** |

## 8. Verification & Post-Implementation Checklist

### `nginx -t` (1.31.2 binárissal)
- Futtasd a célgép 1.31.2 nginx-ével. A `nginx-forward-proxy.conf` relatív `include`-okat (`mime.types`, `vhosts.d/*.conf`) használ, ezért **`-p <prefix>` szükséges** a relatív útvonalak feloldásához: `nginx -p <prefix> -c <prefix>/nginx-forward-proxy.conf -t`.
- Ha a `load_module` ABI-mismatch-et jelez → a célgép nginx-e NEM ABI-azonos a build-del (Step 1 prerequisite sérült).

### Detect-ablak log-megfigyelés (Phase 1)
- [ ] Valós felhasználók `waf=none`-nal logolódnak (nincs false-positive).
- [ ] A `waf=scanner_path`/`empty_ua`/`rate_limit`/`geo_whitelist` találatok a vártak.
- [ ] A `cc=$waf_country` mező alapján a HU IP-set delta elfogadható (location.db `HU` általában teljesebb, mint `ip-list-hu.txt`).

### Cutover smoke-tesztek (curl, Phase 2 után)
- [ ] `GET /.git/config` → 404, `$waf_reason=scanner_path`.
- [ ] Üres User-Agent (`curl -H 'User-Agent:'`) → 404, `$waf_reason=empty_ua`.
- [ ] Nem-HU IP-ről `GET /parastable` → 404, `$waf_reason=geo_whitelist`.
- [ ] Legitim HU kérés (`/`, helyes UA) → 200, `$waf_reason=none`.
- [ ] Küszöb feletti terhelés → 429, `$waf_reason=rate_limit` (HU: >30r/s burst 50 felett; default: >5r/s burst 10 felett).
- [ ] `GET` `Host: 203.0.113.10` → 404 (megmaradt nginx `if` szabály, nem WAF).

### Általános post-implementation
- [ ] A `waf_reason_header` cutover-kor `off` (info-disclosure megelőzése).
- [ ] Egyetlen vhost sem `include`-olja a `nginx-firewall.conf`-ot.
- [ ] A `nginx-1.19.9.1.conf` érintetlen.
- [ ] A `heavybag-stream-mail.conf` NINCS included (inert).
- [ ] A `/opt/imaginarium/conf/heavybag/` fa teljes (`.so` + 9 list + `geodb/location.db`).

## Risks

- **nginx ABI-mismatch**: a `.so` csak az 1.31.2 build-be tölthető. Mitigáció: Step 1 prerequisite + `nginx -t` azonnal kibukik. A vhost-ok már `http3`/`quic`-et igényelnek, amit csak ez a build ad → a bináris-deploy konzisztens, nem extra teher.
- **HU IP-set delta**: `ip-list-hu.txt` → location.db `country=HU` finoman eltérő (általában teljesebb) halmaz. Mitigáció: a detect-ablakban `$waf_country` logolással megfigyelhető, mielőtt élesedik.
- **stream/mail inert**: nincs valós L4/SMTP forgalom; a `heavybag-stream-mail.conf` csak jövőbeli kapacitás, NEM meglévő forgalom migrációja. Aktiválás csak valós backend mellett.
- **`waf_reason_header` éles enforce-ban**: verdikt-disclosure. Mitigáció: cutover-kor kötelezően `off`.
- **`return` a PREACCESS előtt**: olyan `location`, ahol csak `return` van és WAF-verdiktet várnánk, megkerülheti a reputációt. A `parastable.conf` `location`-jei `proxy_pass`-olnak, így a verdikt lefut; nincs ilyen rés.

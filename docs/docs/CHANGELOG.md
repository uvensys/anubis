---
sidebar_position: 999
---

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

<!-- This changes the project to: -->

## v1.21.0: Minfilia Warde

> Please, be at ease. You are among friends here.

In this release, Anubis becomes internationalized, gains the ability to use system load as input to issuing challenges,

### Big ticket changes

The biggest change is that the ["invalid response" after "success" bug](https://github.com/TecharoHQ/anubis/issues/564) is now finally fixed for good by totally rewriting how Anubis' challenge issuance flow works. Instead of generating challenge strings from request metadata (under the assumption that the values being compared against are stable), Anubis now generates random data for each challenge. This data is stored in the active [storage backend](./admin/policies.mdx#storage-backends) for up to 30 minutes. This also fixes [#746](https://github.com/TecharoHQ/anubis/issues/746) and other similar instances of this issue.

In order to reduce confusion, the "Success" interstitial that shows up when you pass a proof of work challenge has been removed.

#### Storage

Anubis now is able to store things persistently [in memory](./admin/policies.mdx#memory), [on the disk](./admin/policies.mdx#bbolt), or [in Valkey](./admin/policies.mdx#valkey) (this includes other compatible software). By default Anubis uses the in-memory backend. If you have an environment with mutable storage (even if it is temporary), be sure to configure the [`bbolt`](./admin/policies.mdx#bbolt) storage backend.

Anubis now supports localized responses. Locales can be added in [lib/localization/locales/](https://github.com/TecharoHQ/anubis/tree/main/lib/localization/locales). This release includes support for the following languages:

- [Brazilian Portugese](https://github.com/TecharoHQ/anubis/pull/726)
- [Chinese (Traditional)](https://github.com/TecharoHQ/anubis/pull/759)
- English
- [French](https://github.com/TecharoHQ/anubis/pull/716)
- [German](https://github.com/TecharoHQ/anubis/pull/741)
- [Spanish](https://github.com/TecharoHQ/anubis/pull/716)
- [Turkish](https://github.com/TecharoHQ/anubis/pull/751)

If facts or local regulations demand, you can set Anubis default language with the `FORCE_LANGUAGE` environment variable:

```sh
FORCE_LANGUAGE=de
```

Anubis can dynamically take action [based on the system load average](./admin/configuration/expressions.mdx#using-the-system-load-average), allowing you to write rules like this:

```yaml
## System load based checks.
# If the system is under high load for the last minute, add weight.
- name: high-load-average
  action: WEIGH
  expression: load_1m >= 10.0 # make sure to end the load comparison in a .0
  weight:
    adjust: 20

# If it is not for the last 15 minutes, remove weight.
- name: low-load-average
  action: WEIGH
  expression: load_15m <= 4.0 # make sure to end the load comparison in a .0
  weight:
    adjust: -10
```

Something to keep in mind about system load average is that it is not aware of the number of cores the system has. If you have a 16 core system that has 16 processes running but none of them is hogging the CPU, then you will get a load average below 16. If you are in doubt, make your "high load" metric at least two times the number of CPU cores and your "low load" metric at least half of the number of CPU cores. For example:

|      Kind | Core count | Load threshold |
| --------: | :--------- | :------------- |
| high load | 4          | `8.0`          |
|  low load | 4          | `2.0`          |
| high load | 16         | `32.0`         |
|  low load | 16         | `8`            |

Also keep in mind that this does not account for other kinds of latency like I/O latency. A system can have its web applications unresponsive due to high latency from a MySQL server but still have that web application server report a load near or at zero.

### Other features and fixes

There are a bunch of other assorted features and fixes too:

- Add `COOKIE_SECURE` option to set the cookie [Secure flag](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cookies#block_access_to_your_cookies)
- Sets cookie defaults to use [SameSite: None](https://web.dev/articles/samesite-cookies-explained)
- Determine the `BIND_NETWORK`/`--bind-network` value from the bind address ([#677](https://github.com/TecharoHQ/anubis/issues/677)).
- Implement a [development container](https://containers.dev/) manifest to make contributions easier.
- Fix dynamic cookie domains functionality ([#731](https://github.com/TecharoHQ/anubis/pull/731))
- Add option for custom cookie prefix ([#732](https://github.com/TecharoHQ/anubis/pull/732))
- Make the [Open Graph](./admin/configuration/open-graph.mdx) subsystem and DNSBL subsystem use [storage backends](./admin/policies.mdx#storage-backends) instead of storing everything in memory by default.
- Allow [Common Crawl](https://commoncrawl.org/) by default so scrapers have less incentive to scrape
- The [bbolt storage backend](./admin/policies.mdx#bbolt) now runs its cleanup every hour instead of every five minutes.

### Potentially breaking changes

The following potentially breaking change applies to native installs with systemd only:

Each instance of systemd service template now has a unique `RuntimeDirectory`, as opposed to each instance of the service sharing a `RuntimeDirectory`. This change was made to avoid [the `RuntimeDirectory` getting nuked any time one of the Anubis instances restarts](https://github.com/TecharoHQ/anubis/issues/748).

If you configured Anubis' unix sockets to listen on `/run/anubis/foo.sock` for instance `anubis@foo`, you will need to configure Anubis to listen on `/run/anubis/foo/foo.sock` and additionally configure your HTTP load balancer as appropriate.

If you need the legacy behaviour, install this [systemd unit dropin](https://www.flatcar.org/docs/latest/setup/systemd/drop-in-units/):

```systemd
# /etc/systemd/system/anubis@.service.d/50-runtimedir.conf
[Service]
RuntimeDirectory=anubis
```

Just keep in mind that this will cause problems when Anubis restarts.

## v1.20.0: Thancred Waters

The big ticket items are as follows:

- Implement a no-JS challenge method: [`metarefresh`](./admin/configuration/challenges/metarefresh.mdx) ([#95](https://github.com/TecharoHQ/anubis/issues/95))
- Implement request "weight", allowing administrators to customize the behaviour of Anubis based on specific criteria
- Implement GeoIP and ASN based checks via [Thoth](https://anubis.techaro.lol/docs/admin/thoth) ([#206](https://github.com/TecharoHQ/anubis/issues/206))
- Add [custom weight thresholds](./admin/configuration/thresholds.mdx) via CEL ([#688](https://github.com/TecharoHQ/anubis/pull/688))
- Move Open Graph configuration [to the policy file](./admin/configuration/open-graph.mdx)
- Enable support for Open Graph metadata to be returned by default instead of doing lookups against the target
- Add `robots2policy` CLI utility to convert robots.txt files to Anubis challenge policies using CEL expressions ([#409](https://github.com/TecharoHQ/anubis/issues/409))
- Refactor challenge presentation logic to use a challenge registry
- Allow challenge implementations to register HTTP routes
- [Imprint/Impressum support](./admin/configuration/impressum.mdx) ([#362](https://github.com/TecharoHQ/anubis/issues/362))
- Fix "invalid response" after "Success!" in Chromium ([#564](https://github.com/TecharoHQ/anubis/issues/564))

A lot of performance improvements have been made:

- Replace internal SHA256 hashing with xxhash for 4-6x performance improvement in policy evaluation and cache operations
- Optimized the OGTags subsystem with reduced allocations and runtime per request by up to 66%
- Replace cidranger with bart for IP range checking, improving IP matching performance by 3-20x with zero heap
  allocations

And some cleanups/refactors were added:

- Fix OpenGraph passthrough ([#717](https://github.com/TecharoHQ/anubis/issues/717))
- Remove the unused `/test-error` endpoint and update the testing endpoint `/make-challenge` to only be enabled in
  development
- Add `--xff-strip-private` flag/envvar to toggle skipping X-Forwarded-For private addresses or not
- Bump AI-robots.txt to version 1.37
- Make progress bar styling more compatible (UXP, etc)
- Add `--strip-base-prefix` flag/envvar to strip the base prefix from request paths when forwarding to target servers
- Fix an off-by-one in the default threshold config
- Add functionality for HS512 JWT algorithm
- Add support for dynamic cookie domains with the `--cookie-dynamic-domain`/`COOKIE_DYNAMIC_DOMAIN` flag/envvar

Request weight is one of the biggest ticket features in Anubis. This enables Anubis to be much closer to a Web Application Firewall and when combined with custom thresholds allows administrators to have Anubis take advanced reactions. For more information about request weight, see [the request weight section](./admin/policies.mdx#request-weight) of the policy file documentation.

TL;DR when you have one or more WEIGHT rules like this:

```yaml
bots:
  - name: gitea-session-token
    action: WEIGH
    expression:
      all:
        - '"Cookie" in headers'
        - headers["Cookie"].contains("i_love_gitea=")
    # Remove 5 weight points
    weight:
      adjust: -5
```

You can configure custom thresholds like this:

```yaml
thresholds:
  - name: minimal-suspicion # This client is likely fine, its soul is lighter than a feather
    expression: weight < 0 # a feather weighs zero units
    action: ALLOW # Allow the traffic through

  # For clients that had some weight reduced through custom rules, give them a
  # lightweight challenge.
  - name: mild-suspicion
    expression:
      all:
        - weight >= 0
        - weight < 10
    action: CHALLENGE
    challenge:
      # https://anubis.techaro.lol/docs/admin/configuration/challenges/metarefresh
      algorithm: metarefresh
      difficulty: 1
      report_as: 1

  # For clients that are browser-like but have either gained points from custom
  # rules or report as a standard browser.
  - name: moderate-suspicion
    expression:
      all:
        - weight >= 10
        - weight < 20
    action: CHALLENGE
    challenge:
      # https://anubis.techaro.lol/docs/admin/configuration/challenges/proof-of-work
      algorithm: fast
      difficulty: 2 # two leading zeros, very fast for most clients
      report_as: 2

  # For clients that are browser like and have gained many points from custom
  # rules
  - name: extreme-suspicion
    expression: weight >= 20
    action: CHALLENGE
    challenge:
      # https://anubis.techaro.lol/docs/admin/configuration/challenges/proof-of-work
      algorithm: fast
      difficulty: 4
      report_as: 4
```

These thresholds apply when no other `ALLOW`, `DENY`, or `CHALLENGE` rule matches the request. `WEIGHT` rules add and remove request weight as needed:

```yaml
bots:
  - name: gitea-session-token
    action: WEIGH
    expression:
      all:
        - '"Cookie" in headers'
        - headers["Cookie"].contains("i_love_gitea=")
    # Remove 5 weight points
    weight:
      adjust: -5

  - name: bot-like-user-agent
    action: WEIGH
    expression: '"Bot" in userAgent'
    # Add 5 weight points
    weight:
      adjust: 5
```

Of note: the default "generic browser" rule assigns 10 weight points:

```yaml
# Generic catchall rule
- name: generic-browser
  user_agent_regex: >-
    Mozilla|Opera
  action: WEIGH
  weight:
    adjust: 10
```

Adjust this as you see fit.

## v1.19.1: Jenomis cen Lexentale - Echo 1

- Return `data/bots/ai-robots-txt.yaml` to avoid breaking configs [#599](https://github.com/TecharoHQ/anubis/issues/599)

## v1.19.0: Jenomis cen Lexentale

Mostly a bunch of small features, no big ticket things this time.

- Record if challenges were issued via the API or via embedded JSON in the challenge page HTML ([#531](https://github.com/TecharoHQ/anubis/issues/531))
- Ensure that clients that are shown a challenge support storing cookies
- Imprint the version number into challenge pages
- Encode challenge pages with gzip level 1
- Add PowerPC 64 bit little-endian builds (`GOARCH=ppc64le`)
- Add `check-spelling` for spell checking
- Add `--target-insecure-skip-verify` flag/envvar to allow Anubis to hit a self-signed HTTPS backend
- Minor adjustments to FreeBSD rc.d script to allow for more flexible configuration.
- Added Podman and Docker support for running Playwright tests
- Add a default rule to throw challenges when a request with the `X-Firefox-Ai` header is set
- Updated the nonce value in the challenge JWT cookie to be a string instead of a number
- Rename cookies in response to user feedback
- Ensure cookie renaming is consistent across configuration options
- Add Bookstack app in data
- Truncate everything but the first five characters of Accept-Language headers when making challenges
- Ensure client JavaScript is served with Content-Type text/javascript.
- Add `--target-host` flag/envvar to allow changing the value of the Host header in requests forwarded to the target service
- Bump AI-robots.txt to version 1.31
- Add `RuntimeDirectory` to systemd unit settings so native packages can listen over unix sockets
- Added SearXNG instance tracker whitelist policy
- Added Qualys SSL Labs whitelist policy
- Fixed cookie deletion logic ([#520](https://github.com/TecharoHQ/anubis/issues/520), [#522](https://github.com/TecharoHQ/anubis/pull/522))
- Add `--target-sni` flag/envvar to allow changing the value of the TLS handshake hostname in requests forwarded to the target service
- Fixed CEL expression matching validator to now properly error out when it receives empty expressions
- Added OpenRC init.d script
- Added `--version` flag
- Added `anubis_proxied_requests_total` metric to count proxied requests
- Add `Applebot` as "good" web crawler
- Reorganize AI/LLM crawler blocking into three separate stances, maintaining existing status quo as default
- Split out AI/LLM user agent blocking policies, adding documentation for each

## v1.18.0: Varis zos Galvus

The big ticket feature in this release is [CEL expression matching support](https://anubis.techaro.lol/docs/admin/configuration/expressions). This allows you to tailor your approach for the individual services you are protecting.

These can be as simple as:

```yaml
- name: allow-api-requests
  action: ALLOW
  expression:
    all:
      - '"Accept" in headers'
      - 'headers["Accept"] == "application/json"'
      - 'path.startsWith("/api/")'
```

Or as complicated as:

```yaml
- name: allow-git-clients
  action: ALLOW
  expression:
    all:
      - >-
        (
          userAgent.startsWith("git/") ||
          userAgent.contains("libgit") ||
          userAgent.startsWith("go-git") ||
          userAgent.startsWith("JGit/") ||
          userAgent.startsWith("JGit-")
        )
      - '"Git-Protocol" in headers'
      - headers["Git-Protocol"] == "version=2"
```

The docs have more information, but here's a tl;dr of the variables you have access to in expressions:

| Name            | Type                  | Explanation                                                                                                                               | Example                                                      |
| :-------------- | :-------------------- | :---------------------------------------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------- |
| `headers`       | `map[string, string]` | The [headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers) of the request being processed.                        | `{"User-Agent": "Mozilla/5.0 Gecko/20100101 Firefox/137.0"}` |
| `host`          | `string`              | The [HTTP hostname](https://web.dev/articles/url-parts#host) the request is targeted to.                                                  | `anubis.techaro.lol`                                         |
| `method`        | `string`              | The [HTTP method](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods) in the request being processed.                    | `GET`, `POST`, `DELETE`, etc.                                |
| `path`          | `string`              | The [path](https://web.dev/articles/url-parts#pathname) of the request being processed.                                                   | `/`, `/api/memes/create`                                     |
| `query`         | `map[string, string]` | The [query parameters](https://web.dev/articles/url-parts#query) of the request being processed.                                          | `?foo=bar` -> `{"foo": "bar"}`                               |
| `remoteAddress` | `string`              | The IP address of the client.                                                                                                             | `1.1.1.1`                                                    |
| `userAgent`     | `string`              | The [`User-Agent`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/User-Agent) string in the request being processed. | `Mozilla/5.0 Gecko/20100101 Firefox/137.0`                   |

This will be made more elaborate in the future. Give me time. This is a [simple, lovable, and complete](https://longform.asmartbear.com/slc/) implementation of this feature so that administrators can get hacking ASAP.

Other changes:

- Use CSS variables to deduplicate styles
- Fixed native packages not containing the stdlib and botPolicies.yaml
- Change import syntax to allow multi-level imports
- Changed the startup logging to use JSON formatting as all the other logs do
- Added the ability to do [expression matching with CEL](./admin/configuration/expressions.mdx)
- Add a warning for clients that don't store cookies
- Disable Open Graph passthrough by default ([#435](https://github.com/TecharoHQ/anubis/issues/435))
- Clarify the license of the mascot images ([#442](https://github.com/TecharoHQ/anubis/issues/442))
- Started Suppressing 'Context canceled' errors from http in the logs ([#446](https://github.com/TecharoHQ/anubis/issues/446))

## v1.17.1: Asahi sas Brutus: Echo 1

- Added customization of authorization cookie expiration time with `--cookie-expiration-time` flag or envvar
- Updated the `OG_PASSTHROUGH` to be true by default, thereby allowing Open Graph tags to be passed through by default
- Added the ability to [customize Anubis' HTTP status codes](./admin/configuration/custom-status-codes.mdx) ([#355](https://github.com/TecharoHQ/anubis/issues/355))

## v1.17.0: Asahi sas Brutus

- Ensure regexes can't end in newlines ([#372](https://github.com/TecharoHQ/anubis/issues/372))
- Add documentation for default allow behavior (implicit rule)
- Enable [importing configuration snippets](./admin/configuration/import.mdx) ([#321](https://github.com/TecharoHQ/anubis/pull/321))
- Refactor check logic to be more generic and work on a Checker type
- Add more AI user agents based on the [ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt) project
- Embedded challenge data in initial HTML response to improve performance
- Added support to use Nginx' `auth_request` directive with Anubis
- Added support to allow to restrict the allowed redirect domains
- Whitelisted [DuckDuckBot](https://duckduckgo.com/duckduckgo-help-pages/results/duckduckbot/) in botPolicies
- Improvements to build scripts to make them less independent of the build host
- Improved the Open Graph error logging
- Added `Opera` to the `generic-browser` bot policy rule
- Added FreeBSD rc.d script so can be run as a FreeBSD daemon
- Allow requests from the Internet Archive
- Added example nginx configuration to documentation
- Added example Apache configuration to the documentation [#277](https://github.com/TecharoHQ/anubis/issues/277)
- Move per-environment configuration details into their own pages
- Added support for running anubis behind a prefix (e.g. `/myapp`)
- Added headers support to bot policy rules
- Moved configuration file from JSON to YAML by default
- Added documentation on how to use Anubis with Traefik in Docker
- Improved error handling in some edge cases
- Disable `generic-bot-catchall` rule because of its high false positive rate in real-world scenarios
- Moved all CSS inline to the Xess package, changed colors to be CSS variables
- Set or append to `X-Forwarded-For` header unless the remote connects over a loopback address [#328](https://github.com/TecharoHQ/anubis/issues/328)
- Fixed mojeekbot user agent regex
- Reduce Anubis' paranoia with user cookies ([#365](https://github.com/TecharoHQ/anubis/pull/365))
- Added support for Open Graph passthrough while using unix sockets
- The Open Graph subsystem now passes the HTTP `HOST` header through to the origin
- Updated the `OG_PASSTHROUGH` to be true by default, thereby allowing Open Graph tags to be passed through by default

## v1.16.0

Fordola rem Lupis

> I want to make them pay! All of them! Everyone who ever mocked or looked down on me -- I want the power to make them pay!

The following features are the "big ticket" items:

- Added support for native Debian, Red Hat, and tarball packaging strategies including installation and use directions
- A prebaked tarball has been added, allowing distros to build Anubis like they could in v1.15.x
- The placeholder Anubis mascot has been replaced with a design by [CELPHASE](https://bsky.app/profile/celphase.bsky.social)
- Verification page now shows hash rate and a progress bar for completion probability
- Added support for [Open Graph tags](https://ogp.me/) when rendering the challenge page. This allows for social previews to be generated when sharing the challenge page on social media platforms ([#195](https://github.com/TecharoHQ/anubis/pull/195))
- Added support for passing the ed25519 signing key in a file with `-ed25519-private-key-hex-file` or `ED25519_PRIVATE_KEY_HEX_FILE`

The other small fixes have been made:

- Added a periodic cleanup routine for the decaymap that removes expired entries, ensuring stale data is properly pruned
- Added a no-store Cache-Control header to the challenge page
- Hide the directory listings for Anubis' internal static content
- Changed `--debug-x-real-ip-default` to `--use-remote-address`, getting the IP address from the request's socket address instead
- DroneBL lookups have been disabled by default
- Static asset builds are now done on demand instead of the results being committed to source control
- The Dockerfile has been removed as it is no longer in use
- Developer documentation has been added to the docs site
- Show more errors when some predictable challenge page errors happen ([#150](https://github.com/TecharoHQ/anubis/issues/150))
- Added the `--debug-benchmark-js` flag for testing proof-of-work performance during development
- Use `TrimSuffix` instead of `TrimRight` on containerbuild
- Fix the startup logs to correctly show the address and port the server is listening on
- Add [LibreJS](https://www.gnu.org/software/librejs/) banner to Anubis JavaScript to allow LibreJS users to run the challenge
- Added a wait with button continue + 30 second auto continue after 30s if you click "Why am I seeing this?"
- Fixed a typo in the challenge page title
- Disabled running integration tests on Windows hosts due to it's reliance on posix features (see [#133](https://github.com/TecharoHQ/anubis/pull/133#issuecomment-2764732309))
- Fixed minor typos
- Added a Makefile to enable comfortable workflows for downstream packagers
- Added `zizmor` for GitHub Actions static analysis
- Fixed most `zizmor` findings
- Enabled Dependabot
- Added an air config for autoreload support in development ([#195](https://github.com/TecharoHQ/anubis/pull/195))
- Added an `--extract-resources` flag to extract static resources to a local folder
- Add noindex flag to all Anubis pages ([#227](https://github.com/TecharoHQ/anubis/issues/227))
- Added `WEBMASTER_EMAIL` variable, if it is present then display that email address on error pages ([#235](https://github.com/TecharoHQ/anubis/pull/235), [#115](https://github.com/TecharoHQ/anubis/issues/115))
- Hash pinned all GitHub Actions

## v1.15.1

Zenos yae Galvus: Echo 1

Fixes a recurrence of [CVE-2025-24369](https://github.com/Xe/x/security/advisories/GHSA-56w8-8ppj-2p4f)
due to an incorrect logic change in a refactor. This allows an attacker to mint a valid
access token by passing any SHA-256 hash instead of one that matches the proof-of-work
test.

This case has been added as a regression test. It was not when CVE-2025-24369 was released
due to the project not having the maturity required to enable this kind of regression testing.

## v1.15.0

Zenos yae Galvus

> Yes...the coming days promise to be most interesting. Most interesting.

Headline changes:

- ed25519 signing keys for Anubis can be stored in the flag `--ed25519-private-key-hex` or envvar `ED25519_PRIVATE_KEY_HEX`; if one is not provided when Anubis starts, a new one is generated and logged
- Add the ability to set the cookie domain with the envvar `COOKIE_DOMAIN=techaro.lol` for all domains under `techaro.lol`
- Add the ability to set the cookie partitioned flag with the envvar `COOKIE_PARTITIONED=true`

Many other small changes were made, including but not limited to:

- Fixed and clarified installation instructions
- Introduced integration tests using Playwright
- Refactor & Split up Anubis into cmd and lib.go
- Fixed bot check to only apply if address range matches
- Fix default difficulty setting that was broken in a refactor
- Linting fixes
- Make dark mode diff lines readable in the documentation
- Fix CI based browser smoke test

Users running Anubis' test suite may run into issues with the integration tests on Windows hosts. This is a known issue and will be fixed at some point in the future. In the meantime, use the Windows Subsystem for Linux (WSL).

## v1.14.2

Livia sas Junius: Echo 2

- Remove default RSS reader rule as it may allow for a targeted attack against rails apps
  [#67](https://github.com/TecharoHQ/anubis/pull/67)
- Whitelist MojeekBot in botPolicies [#47](https://github.com/TecharoHQ/anubis/issues/47)
- botPolicies regex has been cleaned up [#66](https://github.com/TecharoHQ/anubis/pull/66)

## v1.14.1

Livia sas Junius: Echo 1

- Set the `X-Real-Ip` header based on the contents of `X-Forwarded-For`
  [#62](https://github.com/TecharoHQ/anubis/issues/62)

## v1.14.0

Livia sas Junius

> Fail to do as my lord commands...and I will spare him the trouble of blocking you.

- Add explanation of what Anubis is doing to the challenge page [#25](https://github.com/TecharoHQ/anubis/issues/25)
- Administrators can now define artificially hard challenges using the "slow" algorithm:

  ```json
  {
    "name": "generic-bot-catchall",
    "user_agent_regex": "(?i:bot|crawler)",
    "action": "CHALLENGE",
    "challenge": {
      "difficulty": 16,
      "report_as": 4,
      "algorithm": "slow"
    }
  }
  ```

  This allows administrators to cause particularly malicious clients to use unreasonable amounts of CPU. The UI will also lie to the client about the difficulty.

- Docker images now explicitly call `docker.io/library/<thing>` to increase compatibility with Podman et. al
  [#21](https://github.com/TecharoHQ/anubis/pull/21)
- Don't overflow the image when browser windows are small (eg. on phones)
  [#27](https://github.com/TecharoHQ/anubis/pull/27)
- Lower the default difficulty to 5 from 4
- Don't duplicate work across multiple threads [#36](https://github.com/TecharoHQ/anubis/pull/36)
- Documentation has been moved to https://anubis.techaro.lol/ with sources in docs/
- Removed several visible AI artifacts (e.g., 6 fingers) [#37](https://github.com/TecharoHQ/anubis/pull/37)
- [KagiBot](https://kagi.com/bot) is allowed through the filter [#44](https://github.com/TecharoHQ/anubis/pull/44)
- Fixed hang when navigator.hardwareConcurrency is undefined
- Support Unix domain sockets [#45](https://github.com/TecharoHQ/anubis/pull/45)
- Allow filtering by remote addresses:

  ```json
  {
    "name": "qwantbot",
    "user_agent_regex": "\\+https\\:\\/\\/help\\.qwant\\.com/bot/",
    "action": "ALLOW",
    "remote_addresses": ["91.242.162.0/24"]
  }
  ```

  This also works at an IP range level:

  ```json
  {
    "name": "internal-network",
    "action": "ALLOW",
    "remote_addresses": ["100.64.0.0/10"]
  }
  ```

## 1.13.0

- Proof-of-work challenges are drastically sped up [#19](https://github.com/TecharoHQ/anubis/pull/19)
- Docker images are now built with the timestamp set to the commit timestamp
- The README now points to TecharoHQ/anubis instead of Xe/x
- Images are built using ko instead of `docker buildx build`
  [#13](https://github.com/TecharoHQ/anubis/pull/13)

## 1.12.1

- Phrasing in the `<noscript>` warning was replaced from its original placeholder text to
  something more suitable for general consumption
  ([fd6903a](https://github.com/TecharoHQ/anubis/commit/fd6903aeed315b8fddee32890d7458a9271e4798)).
- Footer links on the check page now point to Techaro's brand
  ([4ebccb1](https://github.com/TecharoHQ/anubis/commit/4ebccb197ec20d024328d7f92cad39bbbe4d6359))
- Anubis was imported from [Xe/x](https://github.com/Xe/x)

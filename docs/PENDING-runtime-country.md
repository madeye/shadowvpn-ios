# PENDING CHANGE — apply AFTER the baseline simulator build is green

Status: queued by the orchestrator. The `shadowvpn-ios-build` workflow is producing
a baseline that bypasses a STATIC, build-time-generated CN `chnroute.txt`. The user
now wants this moved to **runtime**, so the user can choose **which country's CIDRs
to bypass** (not just China).

## Delta to apply
1. **Bundle the MaxMind DB at runtime instead of the static list.**
   - Bundle `Shared/Resources/Country.mmdb` into the PacketTunnel target (and app)
     resources. The static `chnroute.txt` is no longer the runtime source (keep
     `core/rust/chnroute-gen` only as an offline utility).
2. **FFI: add a country→CIDR extractor (reuse the geoip logic) WITH a per-country cache.**
   - New C ABI: `int svpn_country_cidrs(const char *mmdb_path, const char *country,
     const char *cache_dir, char *out, int out_cap);` — returns newline-separated
     `a.b.c.d/len` CIDRs for the ISO country code (bytes-needed/`out_cap` truncation
     pattern like the meow `*_convert_*` calls).
   - **Caching (required):** the converted CIDR list for each country is expensive to
     extract from the mmdb, so cache it. On call, look for
     `<cache_dir>/chnroute-<COUNTRY>.txt`; if present, read & return it directly
     (no mmdb walk). Otherwise walk the mmdb once, WRITE the result to that cache file
     atomically, then return it. So each country is converted at most once and reused
     across tunnel starts / app launches. (Invalidate naively: a different/newer
     `Country.mmdb` ⇒ bump a cache version suffix or clear the dir on app update —
     keep it simple, e.g. include the mmdb file size/mtime in the cache filename, or a
     `CACHE_VERSION` constant.)
   - Implement with `maxminddb` + `ipnetwork` + the range→CIDR splitter already in
     `core/rust/chnroute-gen/src/main.rs` (move it into the FFI crate). `maxminddb` is
     pure Rust → cross-compiles to iOS fine; accept the small binary-size cost.
   - `cache_dir` = a subdir of the App Group container (the home dir set via
     `svpn_core_set_home_dir`), so Swift passes e.g. `<home>/cidr-cache`.
   - Optionally also expose `svpn_country_cidrs_count` for UI display.
3. **Profile: add `bypassCountry: String` (default "CN").**
   - Reword `mode` semantics: `full` (tunnel everything) vs `bypass` (split-tunnel,
     bypass the selected country's CIDRs) vs `chinadns` (bypass + split DNS). Rename
     the `chnroute` case → `bypass` if it reads cleaner; keep migration simple.
4. **SVTunnelSettings: build excludedRoutes from the FFI at runtime.**
   - When mode is bypass/chinadns: call `svpn_country_cidrs(mmdbPath, profile.bypassCountry, …)`,
     parse the returned CIDRs → `NEIPv4Route` excluded routes (instead of reading the
     bundled chnroute.txt). Pass the mmdb path + country through config_json / Profile.
5. **dns_intercept (chinadns): use the selected country's set**, not a hardcoded CN.
6. **SettingsView: add a country Picker** (a reasonable ISO-3166 list — at minimum
   CN, HK, TW, JP, KR, US, GB, SG, plus an "Other (code)" entry). Persist to
   `Profile.bypassCountry`.
7. **DESIGN.md + project.yml**: update to reflect mmdb-at-runtime bundling and the
   new FFI symbol; drop the chnroute.txt bundling step.

Keep the rest of the architecture (NE driver, engine, app shell, shared package) as
built by the baseline.

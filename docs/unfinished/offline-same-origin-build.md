# Packaged frontend could not reach its own backend

**State:** fix implemented, CI-green, independently reviewed twice at 0
Critical / 0 High — **never merged**.
**Blocks:** the offline edition release, and therefore both
`OFFLINE_WINDOWS_PACKAGE_ACCEPTED` and `OFFLINE_COMMERCIAL_PACKAGE_ACCEPTED`.

## The bug

The offline edition is a packaged Windows build: a bundled Python runtime
serving the prebuilt SPA **and** the API from a single localhost origin on port
`47613`.

A production package was built, frozen, and put through the acceptance battery.
It failed on a plain, fatal defect:

> The packaged SPA had been built with a **development** API base
> (`http://127.0.0.1:8000`) baked in at build time, while the offline runtime
> serves same-origin on `127.0.0.1:47613`. Every API call from the customer UI
> failed with `ERR_CONNECTION_REFUSED`.

The product was unusable. Not degraded — unusable.

### Why it slipped through

The build was invoked with `--reuse-frontend`, which **skipped** the step that
sets `VITE_API_BASE_URL=""` to produce a same-origin bundle. Vite inlines that
value at build time, so the mistake was baked into immutable bytes and was
invisible to every check that looked at source rather than at the shipped
bundle.

28 of 30 battery items passed on the frozen bytes. The two that mattered were
not expressible as source assertions.

**The lesson, which generalises:** a build-time-inlined constant is part of the
artifact, not the source. If your acceptance oracle only reads source, it
cannot see this class of defect at all.

## The fix

Four files, +307/−5:

1. **`packaging/build_offline_package.py`** — `build_frontend()` forces
   `VITE_API_BASE_URL=""`, runs the customer build, and falls back to invoking
   the Vite binary directly if the package-manager shim misbehaves.
2. **Production refuses `--reuse-frontend`.** The flag that caused the defect
   cannot be used for a production build at all.
3. **`assemble()` fails closed** — it asserts the *shipped bundle* carries no
   development API base, and refuses to assemble if it does.
4. **`packaging/frontend_same_origin.py`** (new, stdlib-only) plus
   `scripts/offline_frontend_same_origin_guard.py`, wired into `audit:all` —
   making this the first offline guard inside the main chain.

The guard greps the built assets for an absolute `http://127.0.0.1:8000` base.
That is an **effect-level** check against the artifact, which is exactly what
the original battery lacked.

## Why it stopped

Nothing technical. The fix was complete, CI-green, and twice reviewed clean.

It stopped because the release process that would consume it requires a
**two-independent-clean-Windows-environment** acceptance run on identical
package bytes, and that process stalled for environmental reasons —
see [offline-two-environment-certification.md](offline-two-environment-certification.md).
With the downstream gate unreachable, merging the fix alone accomplished
nothing, so the branch was left intact rather than merged into a release that
could not complete.

## Resuming

1. Re-implement the four changes above. They are small and well understood.
2. Build **one** package and freeze its hashes (installer, executable, payload
   manifest, frontend manifest, public-key fingerprint).
3. Verify the shipped bundle contains **zero** occurrences of `:8000` and that
   all API calls resolve same-origin to `:47613`.
4. Run the full E1 battery on those exact bytes. Expect ~30 items.
5. Only then attempt the second environment.

### Permanent additions to the E1 battery

Two checks were added as a direct result of this defect and should never be
removed:

- **rendered-frontend check** — assert against the *built* assets, not source
- **same-origin check** — assert zero absolute dev-host API bases in the bundle

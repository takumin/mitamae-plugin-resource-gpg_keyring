# CLAUDE.md

Guidance for Claude Code sessions working in this repository.

## What this is

A [mitamae](https://github.com/itamae-kitchen/mitamae) plugin providing the
`gpg_keyring` resource: it places a GPG public keyring file idempotently
(apt/rpm keyring use case). Implementation lives in `mrblib/` and runs as
mruby inside the mitamae binary — there is no CRuby at runtime, so stick to
mruby-compatible code there. The specs run on CRuby; do not copy CRuby-only
idioms into `mrblib/`.

## Environment setup (required every session)

Fresh containers (e.g. Claude Code on the web) have Ruby but neither the
test gems nor mitamae:

    bundle install
    bundle exec rake test

- rubygems.org is reachable through the session proxy (verified), so
  `bundle install` works; gems are not vendored on purpose.
- If `bundle exec` cannot find `rspec` or `rake` (rbenv images whose
  active version is `system`), prepend the directory shown as
  `EXECUTABLE DIRECTORY` by `gem environment` to `PATH` (in the current
  web container: `/opt/rbenv/versions/3.3.6/bin`). `rake test` itself
  works either way — the rake task invokes rspec through the gem, not
  through `PATH`.
- mitamae is taken from PATH if present; otherwise `spec/spec_helper.rb`
  downloads the pinned release (`MITAMAE_VERSION`, currently v2.0.2) into
  `.bin/`, verified against the `SHA256SUMS` published with that release.
  Override with `MITAMAE=/path/to/binary`.

## Testing

- `bundle exec rake test` — the whole suite, fully offline. This is the
  default gate; keep it green.
- The url/keyserver examples run against a local fixture server on
  `127.0.0.1:39418` started by the suite (`spec/support/local_server.rb`;
  HKP is plain HTTP, so it serves both curl downloads and
  `--receive-keys`). Recipes reference that address literally — keep the
  port in sync if it ever changes.
- Single spec file: `bundle exec rspec spec/integration/export_minimal_spec.rb`
  (narrow further with `-e '<example name>'`)
- `LEGACY_GPG=/usr/bin/gpg1 bundle exec rake test` runs the same suite
  against an old GnuPG (the resource supports 1.4.3 and up). Only
  mitamae gets the legacy binary, via a shim directory prepended to its
  PATH; the spec helpers keep inspecting results with the modern `gpg`
  from PATH. The ed25519 example is skipped there.
- `bundle exec rake clean` removes downloaded binaries and generated
  files (`git clean -xdf`).

## Test layout

- `spec/integration/*_spec.rb` drive `mitamae local` against one recipe
  per case in `test/recipe/` and assert exit status, log content, and
  file state.
- Recipes are plain mitamae recipes: paths resolved from `__FILE__`
  (`test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))`),
  no environment variables. Committed fixtures live in `test/fixture/`
  and must never be modified by a run; writable output goes to
  `test/temporary/`, which is wiped before each example.
- All fixtures are synthetic (revoked uids, multi-key files, subkeys,
  ...) — the suite only reads keys, it never generates them, and no
  example touches a real key or a real server. Regenerate fixtures with
  `bundle exec rake fixtures:regenerate` (all, or a subset via task
  args; see `rakelib/fixtures.rake`); keys are RSA with expiry `never`,
  so committed fixtures cannot rot and stay readable by GnuPG 1.4, which
  has no ECC support — `ed25519.asc` is the deliberate exception
  covering the modern algorithm. Keep both properties that way.
  Regenerating changes the fingerprints, which are written literally in
  `test/recipe/` and `spec/`, so update them together (the task prints
  the new values).

# CLAUDE.md

Guidance for Claude Code sessions working in this repository.

## What this is

A [mitamae](https://github.com/itamae-kitchen/mitamae) plugin providing the
`gpg_keyring` resource: it places a GPG public keyring file idempotently
(apt/rpm keyring use case). Implementation lives in `mrblib/` and runs as
mruby inside the mitamae binary — there is no CRuby at runtime, so stick to
mruby-compatible code there. The specs run on CRuby; do not copy CRuby-only
idioms into `mrblib/`.

## Asking for a decision

When a choice needs the user's call rather than Claude's, show the whole
list of what is currently undecided alongside the question, not just the
one in front of it. A decision made without its neighbouring open items
in view tends to get made twice — once now, narrowly, and again later
once the rest of the list surfaces and changes the earlier answer.

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
- `rake test` needs nothing else. `rake lint` additionally needs
  [aqua](https://aquaproj.github.io/docs/install) on PATH — see below.

## CLI tooling (aqua)

`aqua.yaml` pins the CLI tools the pipeline shells out to (actionlint,
zizmor, pinact, shellcheck) with `aqua-checksums.json` covering linux and
darwin on both architectures, and `checksum.require_checksum` on, so an
unrecorded artifact is a hard failure rather than a warning. `rake tool`
installs them; `rake lint` depends on it.

- Bumping a tool: change the version in `aqua.yaml`, run
  `bundle exec rake checksum` (or `rake fix`), commit both files.
  Renovate raises the version but cannot compute the hashes, so on a bot
  PR the `autofix.ci` workflow runs it instead; the manual command is
  only for local bumps.
- aqua itself is bootstrapped outside the task runner (a tool manager
  cannot install itself); CI uses the `aquaproj/aqua-installer` action
  with `enable_aqua_install: 'false'` so that installing the *tools* stays
  the `rake tool` task's job.
- mitamae is deliberately **not** in `aqua.yaml`: the standard registry's
  entry still expects a `.tar.gz` asset, and mitamae has shipped raw
  binaries since v2, so `itamae-kitchen/mitamae@v2.0.2` cannot resolve.
  `spec_helper`'s own fetch gives the same guarantee (pinned release,
  checksum verified). Move it into `aqua.yaml` once the registry supports
  v2 — and drop one of the two pins when you do.
- Some sandboxes (the Claude Code web container among them) block
  `api.github.com` and sigstore, so aqua's signature checks fail there —
  the sandbox, not the config. `AQUA_DISABLE_GITHUB_ARTIFACT_ATTESTATION`,
  `AQUA_DISABLE_SLSA` and `AQUA_DISABLE_COSIGN` set to `true` get you a
  local run; the hashes in `aqua-checksums.json` are unaffected by them,
  and CI verifies the signatures for real.

## Testing

- `bundle exec rake` — the full pipeline (`lint` then `test`), identical
  to what CI runs. Keep it green.
- `bundle exec rake test` — the whole suite; offline once mitamae is in
  hand, which the environment section above covers. This is the default
  gate; keep it green.
- `bundle exec rake lint` — three passes over `.github/workflows/`:
  actionlint (does it parse; it delegates `run:` blocks to the pinned
  shellcheck rather than a runner image's), zizmor (is it safe) and
  pinact (is every action pinned to a SHA). All three run even when one
  fails, so a finding never hides the next; `rake lint:zizmor` narrows to
  one. zizmor runs `--offline` on purpose — its online audits resolve
  refs through the GitHub API, which would make findings depend on
  whether the caller holds a token, and the pinning they add is what
  pinact answers anyway.
- `bundle exec rake fix` — the write side of the above: regenerates
  `aqua-checksums.json` (`rake checksum`) and pins any action still on a
  tag (`rake pin`). This is what the `autofix.ci` workflow runs.
- `bundle exec rake tool` — `aqua install` for the tools in `aqua.yaml`.
  Idempotent, so it is cheap to depend on.
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
  from PATH. The ed25519 example is skipped there. CI runs this as its
  own job (`legacy`, below); on Debian/Ubuntu the binary comes from
  `apt-get install gnupg1`.
- `bundle exec rake clean` removes downloaded binaries and generated
  files (`git clean -xdf`).

## Continuous integration

`.github/workflows/ci.yml` runs on pushes to `main`, on pull requests,
and on demand. It is a thin orchestrator: every job just calls a rake
task, so CI never runs a command a contributor cannot run locally. Put
new build/test/lint logic in a rake task and call it from the workflow —
not in a `run:` block.

- `lint` runs `rake tool` then `rake lint`; `test` runs `rake test`
  across Ruby 3.2/3.3/3.4/4.0 on `ubuntu-latest`. Bundler 4, which
  `Gemfile.lock` pins, needs Ruby >= 3.2, so that is the floor. Only the
  `lint` job sets up aqua — the suite has no aqua-managed tool.
- `legacy` runs the same `rake test` once more with
  `LEGACY_GPG=/usr/bin/gpg1`, against the GnuPG 1.4.23 that Ubuntu still
  packages as `gnupg1`. It is what keeps the 1.4 branches of the resource
  honest — the runner's own gpg is 2.x and exercises none of them. One
  Ruby (3.4), because the axis under test is gpg rather than Ruby;
  pairing it with the whole Ruby matrix would quadruple the cost for no
  signal. Installing the package is the one `run:` block in the workflow
  that is not a rake task, and it is provisioning, like the Ruby and aqua
  setup actions above it. If Ubuntu ever drops `gnupg1`, the job has to
  build 1.4 from source or go — do not quietly let it fall back to gpg 2,
  which is a green run that checks nothing.
- Linux only: this resource exists to place apt/rpm keyrings, so a macOS
  leg would cost minutes to cover a platform nobody provisions. The
  consequence is that the darwin/aarch64 branch of `spec_helper`'s
  mitamae fetch is not exercised by CI.
- The `ci` job aggregates the rest and is the single check to require in
  branch protection; it only runs (and fails) when something upstream
  failed or was cancelled.
- Permissions start at `{}` and are granted per job, actions are pinned
  to full commit SHAs with a version comment, checkouts do not persist
  credentials, and every job has a timeout.
- `.github/workflows/autofix.yml` regenerates what a bot leaves
  unfinished: it runs `rake fix` on every pull request and hands the diff
  to the autofix.ci app, which pushes the result. Two things about it are
  load bearing. Its `name:` must be exactly `autofix.ci` or the action
  refuses to run, and the job stays `contents: read` — the app owns the
  write side, which is also why its commit re-triggers CI where a
  `GITHUB_TOKEN` push would not. The app has to be installed on the
  repository, like Renovate.
- Renovate (`renovate.json`) keeps the pins fresh — action SHAs, gems and
  the `aqua.yaml` tool versions, the last of which is why it is Renovate
  and not Dependabot: Dependabot has no aqua ecosystem. It extends
  `config:best-practices` (which already implies
  `helpers:pinGitHubActionDigests`, so a newly added action gets pinned to
  a SHA) plus `github>aquaproj/aqua-renovate-config`. Actions, gems and
  aqua tools are grouped into one PR each, weekly. The app has to be
  installed on the repository for any of this to run.
- `BUNDLE_FROZEN` is set workflow-wide, so a `Gemfile.lock` that does not
  match `Gemfile` fails CI instead of being relocked.
- `Gemfile.lock` lists the darwin and aarch64 platforms even though CI
  only runs `x86_64-linux`: it keeps a contributor on a Mac or an arm64
  box from dirtying the lockfile on a plain `bundle install`. Re-add them
  with `bundle lock --add-platform` if it is ever regenerated. The darwin
  entries in `aqua-checksums.json` are there for the same reason —
  without them `require_checksum` would reject the tools on a Mac.
- No caching on purpose: the gems install in seconds and the pinned
  binaries come from GitHub's own release CDN, so a cache would add
  invalidation bugs without buying anything.

## Test layout

- `spec/integration/*_spec.rb` drive `mitamae local` against one recipe
  per case in `test/recipe/` and assert exit status, log content, and
  file state.
- Recipes are plain mitamae recipes: paths resolved from `__FILE__`
  (`test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))`),
  no environment variables. Committed fixtures live in `test/fixture/`
  and must never be modified by a run; writable output goes to
  `test/temporary/`, which is wiped before each example.
- A recipe that names a `homedir` gets `test/temporary/gnupg`. The suite
  populates and inspects it with plain gpg (`import_into_homedir`,
  `homedir_fingerprints`), populating with the gpg under test so a legacy
  run gets a keyring that binary can read. gpg leaves an agent and a
  dirmngr holding the directory, so `wipe_temporary` kills them before
  deleting it.
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

## Pull request review loop

The full flow lives in the `pullreq-merge-flow` skill
(`.claude/skills/pullreq-merge-flow/SKILL.md`, written in Japanese):
when Claude posts `@codex review`, how findings are answered, the three
merge gates, and how to merge from inside and outside a Claude Code
session. The gate check itself is bundled there as
`scripts/merge_gate.sh` — run it as a script, never pasted line by line
into a live shell. Read the skill before requesting a review, judging
whether a PR is approved, or merging anything.

The invariant the skill enforces, restated here so it survives even
when the skill is not loaded: a 👍 on the PR is not by itself approval
of the current head. Approval is the newest clean Codex verdict whose
`Reviewed commit` resolves to the head about to be merged — and the
merge must name that verified revision, not whatever the tip is by
then.

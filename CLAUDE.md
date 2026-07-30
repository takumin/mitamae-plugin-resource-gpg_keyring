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
- `bundle exec rake test` — the whole suite, fully offline. This is the
  default gate; keep it green.
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
  from PATH. The ed25519 example is skipped there.
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

Codex reviews pull requests here automatically. It starts when a draft is
marked ready for review, or on an `@codex review` comment, and says where
it is with reactions on the PR itself, left by
`chatgpt-codex-connector[bot]`:

- 👀 — review running. Nothing to do but wait; the bot takes it back
  when the review ends.
- 👍 — review finished and found nothing. The reaction is the whole
  verdict: a clean review posts no comment and creates no review object,
  so there is nothing else to go looking for.
- Findings arrive as review comments instead, with no reaction left
  behind.

After pushing a fix for a review comment, do all three, in this order:
reply on the thread explaining the fix, mark that thread resolved, then
post a separate `@codex review` comment asking for a re-review. Do not
use `@codex review` to trigger the *first* review — marking a draft ready
does that, and when a PR stops being a draft is the owner's call, never
Claude's.

A 👍 from `chatgpt-codex-connector[bot]` is approval to merge that PR —
of the revision it was left for. A clean review says nothing else: no
issue comment, no review object, just the reaction. So the merge check
cannot ask the verdict which revision it read, because in the case that
ends in a merge there is no verdict to ask. Three things have to be
established instead:

- **Who left it.** A 👍 from anyone else is not it.
- **That nothing is outstanding against this revision.** Findings *do*
  arrive as a review, and a review body names what it read as
  `Reviewed commit: <sha>`. One naming the current head is an open
  objection to exactly what is about to be merged.
- **That the 👍 is newer than the revision.** The reaction sits on the
  PR, not on a commit, and nothing takes it back when the branch moves
  on. After a push the old 👍 is still there to be found, and merging on
  it merges a revision Codex never read.

So a fix pushed for review feedback always has to earn a new 👍 through
`@codex review` — which is why that step is not optional. Merge with a
merge commit, matching the existing history.

Dating the revision is the subtle part, and a commit's own dates cannot
do it: `committer.date` is when the commit was written, not when the
branch received it. Write a commit locally, let Codex review and 👍 the
older head, then push what was already sitting there, and the stale 👍
is newer than the new head's date — the check passes and the merge is of
unreviewed code. What the push *does* create is a check suite, so
`commits/<head>/check-suites` dates the arrival of the revision rather
than the authoring of the commit.

That comparison is conservative in the right direction. GitHub keeps a
reaction's original `created_at`, so if the bot re-reviews a new head
without ever removing its 👍, the timestamp still points at the older
review and the check reads "not approved". It stalls the loop; it never
approves a revision nobody read.

Reactions never arrive over webhooks the way comments and checks do, so a
👍 is only seen by looking for it. Polling the PR is not enough either:
neither the PR payload nor `issue_read` says who reacted, only how many
did. All of it comes from the REST API — this repository is public, so it
needs no token — and every one of these lists pages, so walk them:

    repo=repos/takumin/mitamae-plugin-resource-gpg_keyring
    n=<number>
    bot=chatgpt-codex-connector'[bot]'

    paged() {  # paged <path> [extra-query] -> one JSON object per line
      p=1
      while :; do
        out=$(curl -sS "https://api.github.com/$1?per_page=100&page=$p&${2:-}")
        # An error is a JSON object, not an array, and `jq length` counts
        # its keys - so testing only for emptiness spins forever, at full
        # speed, against an API that is already refusing.
        if [ "$(jq -r type <<<"$out")" != array ]; then
          echo "github api: $(jq -r '.message // .' <<<"$out")" >&2
          return 1
        fi
        [ "$(jq length <<<"$out")" -eq 0 ] && break
        jq -c '.[]' <<<"$out"
        p=$((p + 1))
      done
    }

    # Every lookup is captured whole before anything reads it, so a list
    # that failed halfway stops the check. `paged ... | jq ...` cannot do
    # that: a pipeline reports the status of its *last* command, so
    # paged's `return 1` is discarded and jq's happy exit stands in for
    # it - leaving a truncated list that reads like a complete one.
    plus1=$(paged "$repo/issues/$n/reactions" "content=%2B1") || exit 1
    reviews=$(paged "$repo/pulls/$n/reviews")                 || exit 1
    # Read the head *after* the lists, never before. A push that lands
    # while they are being walked then leaves the head newer than the 👍,
    # so the check reads "not approved". Read it first and that same push
    # reads as approved - for the revision it just replaced.
    head=$(curl -sS "https://api.github.com/$repo/pulls/$n" | jq -r '.head.sha // empty')
    [ -n "$head" ] || { echo "github api: no head sha" >&2; exit 1; }

    # When this revision arrived. The push creates the check suite, so
    # this dates the branch receiving the commit, not someone writing it.
    arrived=$(curl -sS "https://api.github.com/$repo/commits/$head/check-suites?per_page=100" \
      -H 'Accept: application/vnd.github+json' |
      jq -r '[.check_suites[].created_at] | min // empty')
    [ -n "$arrived" ] ||
      { echo "no: no check suite for $head, cannot date the push" >&2; exit 1; }

    plus=$(jq -r --arg b "$bot" 'select(.user.login==$b) | .created_at' <<<"$plus1" |
      sort | tail -1)

    # A findings review names an abbreviated revision; the head starting
    # with it is the match. This is the one place a prefix test is the
    # right question - it is looking for an objection, so the loose read
    # blocks the merge rather than waving it through.
    findings=$(jq -r --arg b "$bot" --arg h "$head" \
      'select(.user.login==$b)
       | (.body // "" | capture("Reviewed commit:\\*\\* `(?<s>[0-9a-f]+)`")? | .s) as $s
       | select($s != null) | select($h | startswith($s)) | .submitted_at' <<<"$reviews" |
      sort | tail -1)

    # Every check above only *prints* until something branches on it. Each
    # of these is one of the three gates, and each exits rather than
    # falling through to the merge.
    [ -n "$plus" ]     || { echo "no: no 👍 from the bot" >&2; exit 1; }
    [ -z "$findings" ] ||
      { echo "no: a findings review names this head ($findings)" >&2; exit 1; }
    [[ "$plus" > "$arrived" ]] ||
      { echo "no: 👍 ($plus) predates this revision ($arrived)" >&2; exit 1; }

Then merge — and this is where a Claude Code session differs from a
terminal. The REST endpoint is refused outright:

    curl -X PUT ".../pulls/$n/merge"
    403 {"message":"Merging into a protected base branch is not permitted
         for this session type."}

so the merge goes through the GitHub MCP server's `merge_pull_request`
with `merge_method: "merge"`. That tool takes no `sha` precondition,
which the REST call did, so nothing server-side refuses the merge if the
head moved between the check and the call. Read the head as the last
thing before merging and keep the gap short; on a branch someone else
pushes to, re-run the whole check rather than trusting an old reading.

A lookup that only prints decides nothing; read as a script, an absent 👍
or an open findings review would scroll past and the merge would go ahead
anyway — which is what those `exit`s are for.

Both lists are read the same way and for the same reason: 30 reactions
per page by default, 100 reviews per page at most, and taking only the
first page of either loses the newest entry on a long-running PR. The
reaction lookup then reads as no 👍, and the findings lookup misses an
objection — the first stalls the loop, the second is the one that merges
something it should not. `content=%2B1` asks for 👍 alone; drop it to see
every reaction. `%2B` rather than `+`, which would decode as a space.

`pulls/<number>/reviews` alone would be tidier, since its entries carry a
`commit_id` field, but a clean verdict never creates a review object —
which is exactly the case that ends in a merge.

A failed lookup is not the same answer as an empty one: treat it as "not
known", never as "no approval". That distinction only survives if the
failure is allowed to reach you, which is why the lookups above are run
as a script — `bash -c` or a file, not pasted line by line into a live
shell, where `exit 1` would close the shell rather than abandon the
check, and where a `||` that never fires is easy not to notice.

In a Claude Code session `api.github.com` is reached through the session
proxy, which authenticates the request for you: an unauthenticated
`curl` still reports the 15000/hour limit rather than 60. Elsewhere, pass
`-H "Authorization: Bearer $GITHUB_TOKEN"`, because 60 an hour against a
round that costs roughly ten is a real ceiling.

Where `gh` is installed, `gh api --paginate` walks these lists for you,
authenticates, and fails on an error response, which is worth using
interactively. The shell above is what the doc records because a fresh
container has `curl` and `jq` and not `gh`.

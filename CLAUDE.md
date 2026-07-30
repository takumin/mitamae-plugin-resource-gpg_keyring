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
shellcheck) with `aqua-checksums.json` covering linux and darwin on both
architectures, and `checksum.require_checksum` on, so an unrecorded
artifact is a hard failure rather than a warning. `rake tool` installs
them; `rake lint` depends on it.

- Bumping a tool: change the version in `aqua.yaml`, run
  `bundle exec rake checksum`, commit both files. Renovate raises the
  version but cannot compute the hashes, so on a bot PR the
  `autofix.ci` workflow runs that same task and pushes the result; the
  manual command is only for local bumps.
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
  `api.github.com` and sigstore, which makes aqua's GitHub Artifact
  Attestations check fail for actionlint. That is the sandbox, not the
  config; `AQUA_DISABLE_GITHUB_ARTIFACT_ATTESTATION=true` gets you a local
  run, and CI verifies for real.

## Testing

- `bundle exec rake` — the full pipeline (`lint` then `test`), identical
  to what CI runs. Keep it green.
- `bundle exec rake test` — the whole suite, fully offline. This is the
  default gate; keep it green.
- `bundle exec rake lint` — actionlint over `.github/workflows/`. It
  depends on `rake tool`, so the pinned actionlint is installed first.
  actionlint delegates `run:` blocks to shellcheck, which is pinned
  alongside it: the findings are the same everywhere instead of tracking
  whatever shellcheck a runner image happens to ship.
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
- `.github/workflows/autofix.yml` regenerates what a bot cannot: it runs
  `rake checksum` on every pull request and hands the diff to the
  autofix.ci app, which pushes the fix. Two things about it are load
  bearing. Its `name:` must be exactly `autofix.ci` or the action
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
- 👍 — review finished and found nothing.
- Findings arrive as review comments instead, with no reaction left
  behind.

After pushing a fix for a review comment, do all three, in this order:
reply on the thread explaining the fix, mark that thread resolved, then
post a separate `@codex review` comment asking for a re-review. Do not
use `@codex review` to trigger the *first* review — marking a draft ready
does that, and when a PR stops being a draft is the owner's call, never
Claude's.

A 👍 from `chatgpt-codex-connector[bot]` is approval to merge that PR —
of the revision it was left for. Two things can make a 👍 the wrong
signal, and both have to be checked:

- **Who left it.** A 👍 from anyone else is not it.
- **Which commit it was left for.** The 👍 sits on the PR, not on a
  commit, and nothing takes it back when the branch moves on. After a
  push the old 👍 is still there to be found, and merging on it merges a
  revision Codex never read. Every Codex verdict names the revision it
  read as `Reviewed commit: <sha>`; require that to be the current head.
- **What that verdict actually said.** A 👍 left by an earlier clean
  review survives a later review that found problems, so "a 👍 exists"
  and "the newest verdict names this head" can both be true while that
  newest verdict is a list of findings. Require it to be the clean kind.
  Which kind it is never appears in the text — a clean pass arrives as an
  issue comment and findings as a review — so it has to be carried from
  the list the entry came out of.

So a fix pushed for review feedback always has to earn a new 👍 through
`@codex review` — which is why that step is not optional. Merge with a
merge commit, matching the existing history, and bind the merge to the
revision that was checked rather than to whatever the tip is by then.

Reactions never arrive over webhooks the way comments and checks do, so a
👍 is only seen by looking for it. Polling the PR is not enough either:
neither the PR payload nor `issue_read` says who reacted, only how many
did. All of it comes from the REST API — this repository is public, so it
needs no token — and every one of these lists pages, so walk them:

    repo=repos/takumin/mitamae-plugin-resource-gpg_keyring
    n=<number>

    paged() {  # paged <path> [extra-query] -> one JSON object per line
      p=1
      while :; do
        out=$(curl -sS "https://api.github.com/$1?per_page=100&page=$p&$2")
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
    comments=$(paged "$repo/issues/$n/comments")              || exit 1
    reviews=$(paged "$repo/pulls/$n/reviews")                 || exit 1
    # Read the head *after* the lists, never before. A push that lands
    # while they are being walked then leaves the head newer than anything
    # the verdicts can name, so the check reads "not approved". Read it
    # first and that same push reads as approved - for the revision it
    # just replaced.
    head=$(curl -sS "https://api.github.com/$repo/pulls/$n" | jq -r '.head.sha // empty')
    [ -n "$head" ] || { echo "github api: no head sha" >&2; exit 1; }

    # is there a 👍 from the bot?
    plus=$(jq -r 'select(.user.login=="chatgpt-codex-connector[bot]") | .created_at' <<<"$plus1")

    # what was the newest verdict, on which revision?
    newest=$( { jq -c '. + {verdict:"clean"}'    <<<"$comments"
                jq -c '. + {verdict:"findings"}' <<<"$reviews"; } |
      jq -r 'select(.user.login=="chatgpt-codex-connector[bot]")
           | (.body | capture("Reviewed commit:\\*\\* `(?<s>[0-9a-f]+)`")? | .s) as $s
           | select($s != null)
           | [(.submitted_at // .created_at), .verdict, $s] | @tsv' | sort | tail -1)
    IFS=$'\t' read -r _ kind sha <<<"$newest"

    # Every check above only *prints* until something branches on it. Each
    # of these is one of the three gates, and each exits rather than
    # falling through to the merge.
    [ -n "$plus" ]      || { echo "no: no 👍 from the bot"           >&2; exit 1; }
    [ -n "$sha" ]       || { echo "no: no verdict names a revision"  >&2; exit 1; }
    [ "$kind" = clean ] || { echo "no: newest verdict is $kind"      >&2; exit 1; }

    # The verdict names an abbreviated revision. Resolve it and require it
    # to *be* the head: asking whether the head merely starts with those
    # characters is a weaker question, and a different commit can answer
    # it. GitHub 422s on an abbreviation it cannot resolve, which `// empty`
    # turns into a mismatch rather than a pass.
    reviewed=$(curl -sS "https://api.github.com/$repo/commits/$sha" | jq -r '.sha // empty')
    [ "$reviewed" = "$head" ] ||
      { echo "no: verdict names ${reviewed:-$sha}, head is $head" >&2; exit 1; }

    # only now, and only for the revision that was checked. --fail-with-body
    # because curl exits 0 on a 409/403 otherwise, and "nothing merged"
    # would read as success.
    curl -sS --fail-with-body -X PUT "https://api.github.com/$repo/pulls/$n/merge" \
      -H "Authorization: Bearer $GITHUB_TOKEN" \
      -d "$(jq -n --arg sha "$head" '{sha: $sha, merge_method: "merge"}')" ||
      { echo "merge refused" >&2; exit 1; }

The verdict line has to read `clean` and name the head sha, and the
merge does not run until it does — which is what those four `exit`s are
for. A lookup that only prints decides nothing; read as a script, an
absent 👍 or a findings verdict would scroll past and the merge would go
ahead anyway. The `sha` precondition does not cover this: it asks
whether the head moved, never whether it was approved.

`[ -n "$sha" ]` is there because an empty `$sha` would otherwise be sent
to the commits endpoint as a bare path, whose answer is not a commit and
not a refusal to resolve one. Nothing reaches it today: the jq filter
drops entries with no `Reviewed commit`, and a verdict that is missing
entirely fails the `clean` test first. It costs one line and covers the
case where those stop being true.

The abbreviation is why the revision gate resolves rather than compares
prefixes. Codex writes 10 hex characters — 40 bits, which is not a wall —
and "the head starts with these characters" is a different, weaker
question than "this is the head". Resolving turns it back into the
question worth asking, for one request. GitHub needs at least 7
characters and answers 422 for anything it cannot resolve, so a garbage
or truncated sha fails the gate instead of skipping it.

The `verdict`
tag is stamped on from the list each entry came out of, because it is
nowhere in the entry itself; entries with no `Reviewed commit` line are
dropped so a stray bot comment cannot win the sort.

Passing the check is not the same as still passing it a moment later, so
the merge names the revision it was given: `sha` is a precondition, and
GitHub refuses with 409 if the head has moved since. Ordering the reads
carefully makes a push *during* the check fail safe; only the
precondition covers a push *after* it. Without it every gate here is
advisory — they all describe a revision, and the merge would take
whatever is at the tip.

Both lookups are read the same way and for the same reason: 30 reactions
per page by default, 100 comments or reviews per page at most, and taking
only the first page of either loses the newest entry on a long-running
PR. The reaction lookup then reads as no 👍, and the revision lookup
names a stale sha — both of which stall the loop rather than break it,
which is the failure that never announces itself. `content=%2B1` asks for
👍 alone; drop it to see every reaction. `%2B` rather than `+`, which
would decode as a space.

That split — `Reviewed commit` in an issue comment when the review is
clean, in the review body when it has findings — is why both lists are
read, and it is also the only thing that says which kind of verdict an
entry is. The sha it carries is abbreviated, so resolve it through the
commits endpoint and require the full result to equal the head — never
compare it as a prefix of the head.

Do not reach for timestamps here. Comparing the 👍 against the head
commit's `committer.date` looks equivalent and is not: that date is when
the commit was written, not when the branch received it. Write a commit
locally, let Codex review and 👍 the older head, then push what was
already sitting there, and the stale 👍 is newer than the new head's
date — the check passes and the merge is of unreviewed code. Codex's own
`Reviewed commit` has no such gap: it names a revision rather than a
moment.

`pulls/<number>/reviews` alone would be tidier, since its entries carry a
`commit_id` field, but a clean verdict never creates a review object —
which is exactly the case that ends in a merge.

A failed lookup is not the same answer as an empty one: treat it as "not
known", never as "no approval". That distinction only survives if the
failure is allowed to reach you, which is why the lookups above are run
as a script — `bash -c` or a file, not pasted line by line into a live
shell, where `exit 1` would close the shell rather than abandon the
check, and where a `||` that never fires is easy not to notice.
Unauthenticated polling gets 60 requests
an hour, and a round over both PRs costs roughly ten, so this is a real
ceiling rather than a theoretical one — pass `-H "Authorization: Bearer
$GITHUB_TOKEN"` when a token is around and the limit is 5000 instead.

Where `gh` is installed, `gh api --paginate` walks these lists for you,
authenticates, and fails on an error response, which is worth using
interactively. The shell above is what the doc records because a fresh
container has `curl` and `jq` and not `gh`.

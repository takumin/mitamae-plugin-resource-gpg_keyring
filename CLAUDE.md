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
  args; see `rakelib/fixtures.rake`); keys are ed25519 with expiry
  `never` so committed fixtures cannot rot — keep it that way.
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
merge commit, matching the existing history.

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
        [ "$(jq 'length' <<<"$out")" -eq 0 ] && break
        jq -c '.[]' <<<"$out"
        p=$((p + 1))
      done
    }

    # is there a 👍 from the bot?
    paged "$repo/issues/$n/reactions" "content=%2B1" |
      jq -r 'select(.user.login=="chatgpt-codex-connector[bot]") | .created_at'

    # what was the newest verdict, on which revision?
    curl -sS "https://api.github.com/$repo/pulls/$n" | jq -r .head.sha
    { paged "$repo/issues/$n/comments" | jq -c '. + {verdict:"clean"}'
      paged "$repo/pulls/$n/reviews"   | jq -c '. + {verdict:"findings"}'; } |
      jq -r 'select(.user.login=="chatgpt-codex-connector[bot]")
           | (.body | capture("Reviewed commit:\\*\\* `(?<s>[0-9a-f]+)`")? | .s) as $s
           | select($s != null)
           | [(.submitted_at // .created_at), .verdict, $s] | @tsv' | sort | tail -1

That last line has to read `clean` and name the head sha. The `verdict`
tag is stamped on from the list each entry came out of, because it is
nowhere in the entry itself; entries with no `Reviewed commit` line are
dropped so a stray bot comment cannot win the sort.

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
entry is. The sha is abbreviated, so compare it as a prefix of the head
sha.

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

Where `gh` is installed, `gh api --paginate` walks these lists for you
and `--jq` filters them, which is worth using interactively. The shell
above is what the doc records because a fresh container has `curl` and
`jq` and not `gh`.

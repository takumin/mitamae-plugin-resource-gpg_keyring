# mitamae-plugin-resource-gpg_keyring

[![CI](https://github.com/takumin/mitamae-plugin-resource-gpg_keyring/actions/workflows/ci.yml/badge.svg)](https://github.com/takumin/mitamae-plugin-resource-gpg_keyring/actions/workflows/ci.yml)

A [mitamae](https://github.com/itamae-kitchen/mitamae) plugin that places a
GPG public keyring file idempotently (e.g. apt keyrings referenced by
`Signed-By`).

The key is fetched from a URL or a keyserver, verified against the
fingerprint the recipe pins, and exported into the target file. The file is
only rewritten when it does not already carry that key.

## Requirements

- mitamae (developed and tested against v2.0.2)
- `gpg` on the target node - GnuPG 1.4.3 or newer (see
  [GnuPG versions](#gnupg-versions))
- `curl` on the target node

Both commands are checked before every action, including `:delete`, and a
missing one stops the run with an explicit message.

## Installation

mitamae loads plugins from `plugins/` (override with `--plugins=PATH`), and
only from directories named `{,m}itamae-plugin-resource-*`. Add this
repository under that name, as a submodule or a plain copy:

```console
$ git submodule add https://github.com/takumin/mitamae-plugin-resource-gpg_keyring.git \
    plugins/mitamae-plugin-resource-gpg_keyring
$ mitamae local recipe.rb
```

## Usage

Fetch from a URL:

```ruby
gpg_keyring '/etc/apt/keyrings/example.gpg' do
  fingerprint 'F487F0CB3B38FC5CE3512CC4F18EC5EF947FFAD2'
  user_id     'Takumi Takahashi <takumiiinn@gmail.com>'
  url         'https://github.com/takumin.gpg'
  owner       'root'
  group       'root'
  mode        '644'
end
```

Receive from a keyserver instead (the default when `url` is omitted):

```ruby
gpg_keyring '/etc/apt/keyrings/example.gpg' do
  fingerprint 'F487F0CB3B38FC5CE3512CC4F18EC5EF947FFAD2'
  keyserver   'hkps://keyserver.ubuntu.com'
end
```

Keep the key in a GnuPG homedir of your own, instead of the throwaway one
every run otherwise uses:

```ruby
gpg_keyring '/etc/apt/keyrings/example.gpg' do
  fingerprint 'F487F0CB3B38FC5CE3512CC4F18EC5EF947FFAD2'
  homedir     '/var/lib/example/gnupg'
end
```

Remove a keyring:

```ruby
gpg_keyring '/etc/apt/keyrings/example.gpg' do
  action      :delete
  fingerprint 'F487F0CB3B38FC5CE3512CC4F18EC5EF947FFAD2'
end
```

## Attributes

| Attribute     | Type   | Default                   | Description |
| ------------- | ------ | ------------------------- | ----------- |
| `fingerprint` | String | -- (required)             | Full 40 hex digit fingerprint of the **primary** key. Selects and pins the key. |
| `user_id`     | String | --                        | Asserted user id. The run stops unless the key carries this exact uid. |
| `url`         | String | --                        | Where to fetch the key from. Anything `curl` accepts, including `file://`. |
| `keyserver`   | String | `hkps://keys.openpgp.org` | Keyserver used when `url` is not given. |
| `homedir`     | String | -- (throwaway)            | A GnuPG homedir that outlives the run and doubles as a key store. |

The resource inherits mitamae's `file` resource, so its attributes
(`owner`, `group`, `mode`, `path`, ...) work as usual.

## Actions

| Action    | Description |
| --------- | ----------- |
| `:create` | Default. Places the keyring file, fetching the key when needed. |
| `:delete` | Removes the file if it exists. No key is read or fetched, and a `homedir` is left alone. |

## Behavior

### Output format

The export format follows the file extension: `.gpg` is written as binary
(what apt's `Signed-By` expects), anything else as ASCII armor.

### Fingerprint normalization

`fingerprint` is normalized before use - surrounding whitespace, embedded
spaces, lowercase and a `0x` prefix are all accepted, so a fingerprint
pasted straight out of `gpg --fingerprint` works. What remains must be 40
characters; short key ids are rejected rather than silently resolved.

Passing a **sub** key fingerprint is reported as its own error naming the
primary key, because treating it as a plain mismatch would re-fetch and
rewrite the file on every run.

### `user_id` is an assertion

`user_id` is an assertion, not a convergible attribute: when the key's valid
uids do not contain the exact string, the run stops. It exists to catch
fingerprint mix-ups early and to keep recipes self-documenting. It is **not
a security boundary** - the fingerprint is what selects and pins the key.

Revoked and expired uids do not count as valid. If the key owner revokes the
uid your recipe asserts, provisioning fails from that day on by design;
update the recipe to a currently valid uid.

Omitting `user_id` skips the check entirely, which is the right choice for
keys served without any uid - keys.openpgp.org does that for unverified
keys.

The comparison is made against the decoded uid, so one containing `:` or
`\` matches the natural string a recipe writes rather than the `\x3a`
escapes gpg prints.

### Keyring contents

Keys are exported with `--export-options export-minimal`, so the placed file
stays deterministic regardless of third-party signatures attached to the
source. Revocation information survives (revocations are self-signatures).
Already-placed files are only rewritten when the fingerprint changes, so
enabling this does not shrink existing files.

Imports use `--import-options import-minimal` as well (`--keyserver-options
import-minimal` on the receive path, which is where gpg takes them from).
That is a defense, not redundancy: keys come from arbitrary URLs, and
importing a key padded with tens of thousands of third-party signatures
otherwise hangs the run.

One file, one key on writes: a file containing several keys is readable as
long as the desired key is among them, but the resource refuses to rewrite a
multi-key file that does not contain the desired key.

### Idempotency and fetching

The key is fetched only when the target file is missing or its primary
fingerprint differs from `fingerprint` - a converged run touches the network
not at all. The fetched key is verified before the export, so a key that is
not what the recipe claims never reaches the target file.

Network fetches (both `curl` and `--recv-keys`) are retried up to 3 times
with exponential backoff (2s, then 4s), because public keyservers fail
intermittently.

Every gpg invocation is made with `--no-options`, `--batch`, `--quiet`,
`--with-colons` and `--trust-model always`: no `gpg.conf` gets a say in what
is written, nothing consults the web of trust, and no trustdb is built
behind the caller's back.

### The homedir

Without `homedir`, every run works in a throwaway directory and nothing
survives it.

A `homedir` outlives the run and doubles as a key store: a key already in it
is exported without contacting `url` or `keyserver` at all, so a
pre-populated homedir works on hosts without network access. Nothing
refreshes such a key on its own - drop it from the homedir and run again.
The directory is created with mode 0700 when missing, an existing one keeps
its permissions, and the `:delete` action only removes the keyring file. A
run that finds no such directory says so with a warning before creating one:
a homedir that is not there is as easily a typo in the recipe as a first
run.

Fetching never touches your homedir. Downloading, receiving and importing
all happen in a throwaway one, and what your homedir is handed afterwards is
the placed keyring itself: the same verified, `export-minimal` key that went
into the file, and nothing else. A run that stops on the fingerprint or
`user_id` assertion leaves it exactly as it was: uncreated if it was not
there, and otherwise untouched. gpg initializes any homedir it is pointed at
- it creates the store its configuration names, builds a trustdb, and starts
keyboxd where that is the store - so the lookup deciding whether a fetch is
needed is made over a throwaway copy of your keys, and your homedir is
pointed at only once the key has been verified. Keys are found there whether
they live in `pubring.kbx`, 1.4's `pubring.gpg`, or keyboxd's
`public-keys.d`; which of them is read follows the `use-keyboxd` the gpg in
use resolves, out of the homedir's `common.conf` and the system-wide one
alike.

Reading an already-placed keyring is a throwaway homedir too, so keys you
keep in yours never end up in the file.

The keyring file is written after the homedir has been updated, so a target
*inside* the homedir lands on whatever gpg keeps under that name. A path
naming one of gpg's own files (`pubring.kbx`, `pubring.gpg`, `trustdb.gpg`,
`tofu.db`, any `*.conf`, the agent sockets, and the `~` backups and `.lock`
files gpg derives from those names) or anything inside one of its
directories (`public-keys.d`, `private-keys-v1.d`, `openpgp-revocs.d`,
`crls.d`, `tofu.d`) stops the run; any other path in there works and is
warned about once. The check is on the name rather than on what happens to
be there already, and it is made for the `:delete` action too. The paths are
compared as written, fully resolved, and by walking the target's own
components, so neither a symlink nor a second name for the homedir can
present a reserved entry as something else; a target that is a hard link to
one of those files is refused as well. Keep the keyring outside the homedir
and the question does not arise.

## GnuPG versions

GnuPG 1.4.3 or newer, where `import-minimal` and `export-minimal` appeared.
The version is checked before every action, so an older `gpg` stops the run
by name instead of failing later as an unknown-option error; a version
string that cannot be read is left alone rather than refused. The check
reads GnuPG's own banner (`gpg (GnuPG) 2.4.4`), so a wrapper that announces
itself first does not get its own version mistaken for gpg's.

GnuPG's own interface differs across that range, which the resource absorbs
so recipes do not have to:

- Sub key fingerprints appear in `--with-colons` listings only when
  `--fingerprint` is repeated, until 2.1.15 made them unconditional.
- 1.4 inlines the primary uid into the `pub` record unless
  `--fixed-list-mode` is given, leaving no uid record for `user_id` to
  match against.
- 1.4 knows `--recv-keys` but not its `--receive-keys` alias.

Two limits belong to GnuPG itself rather than to this resource: 1.4 cannot
read ECC keys (ed25519 and friends) at all, and whether it reaches an
`hkps://` keyserver depends on how it was built. Prefer `url` when in doubt.
An ECC key handed to a build without ECC support stops the run with the
algorithm named - gpg's own answer there is `no valid user IDs`, which is
the one thing that is not wrong with the key.

## Development

```console
$ bundle install
$ bundle exec rake        # lint then test, identical to CI
```

`rake test` is the suite on its own and needs nothing but the gems and a
mitamae binary. It drives the real `mitamae local` binary against the
recipes in `test/recipe/`, and once that binary is in hand the examples
themselves are offline: url and keyserver cases are served by a local
fixture server started by the suite, and all keys are committed synthetic
fixtures.

Getting the binary is the one step that can reach the network. mitamae is
taken from `PATH` when present, and otherwise from `.bin/`, which a first
run populates by downloading a pinned release from GitHub and verifying it
against the checksums published with it. So on a host with no network the
suite runs only once mitamae is already available - on `PATH`, cached in
`.bin/` by an earlier run, or named explicitly with
`MITAMAE=/path/to/binary`.

`rake lint` checks `.github/workflows/` with actionlint, zizmor and pinact,
pinned by [aqua](https://aquaproj.github.io/) in `aqua.yaml` and installed
by `rake tool`, so it needs aqua on `PATH`. `rake fix` is its write side
(aqua checksums, action SHA pins), and is what the autofix.ci workflow runs
on pull requests.

```console
$ bundle exec rspec spec/integration/export_minimal_spec.rb  # single file
$ LEGACY_GPG=/usr/bin/gpg1 bundle exec rake test             # against GnuPG 1.4
$ bundle exec rake clean                                     # git clean -xdf
```

`rake clean` is `git clean -xdf` with no pathspec, so it removes every
untracked file in the checkout - not just the downloaded binary and the
temporary keyrings, but also work that has not been committed or staged
yet. Commit or stash first, or run `git clean -xdn` to see what would go.

CI runs the suite on Ruby 3.2 through 4.0, plus one more pass against the
GnuPG 1.4.23 Ubuntu ships as `gnupg1`, which is what keeps the 1.4 branches
of the resource honest.

## License

MIT. See [LICENSE](LICENSE).

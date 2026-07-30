# mitamae-plugin-resource-gpg_keyring

[![CI](https://github.com/takumin/mitamae-plugin-resource-gpg_keyring/actions/workflows/ci.yml/badge.svg)](https://github.com/takumin/mitamae-plugin-resource-gpg_keyring/actions/workflows/ci.yml)

A [mitamae](https://github.com/itamae-kitchen/mitamae) plugin that places a
GPG public keyring file idempotently (e.g. apt keyrings referenced by
`Signed-By`).

```ruby
gpg_keyring '/etc/apt/keyrings/example.gpg' do
  fingerprint 'F487F0CB3B38FC5CE3512CC4F18EC5EF947FFAD2'
  user_id     'Takumi Takahashi <takumiiinn@gmail.com>'
  url         'https://github.com/takumin.gpg' # or keyserver 'hkps://...'
end
```

`fingerprint` is the only required attribute. Without `url` the key is
received from `keyserver` (default: `hkps://keys.openpgp.org`). Attributes
of the file resource (`owner`, `mode`, ...) work as usual.

The key is handled in a throwaway GnuPG homedir unless `homedir` names one
to keep:

```ruby
gpg_keyring '/etc/apt/keyrings/example.gpg' do
  fingerprint 'F487F0CB3B38FC5CE3512CC4F18EC5EF947FFAD2'
  homedir     '/var/lib/example/gnupg'
end
```

## Semantics worth knowing

- `user_id` is an assertion, not a convergible attribute: when the key's
  valid uids do not contain the exact string, the run stops. It exists to
  catch fingerprint mix-ups early and to keep recipes self-documenting.
  It is **not a security boundary** - the fingerprint is what selects and
  pins the key.
- Revoked and expired uids do not count as valid. If the key owner
  revokes the uid your recipe asserts, provisioning fails from that day
  on by design; update the recipe to a currently valid uid.
- Keys are exported with `--export-options export-minimal`, so the placed
  file stays deterministic regardless of third-party signatures attached
  to the source. Revocation information survives (revocations are
  self-signatures). Already-placed files are only rewritten when the
  fingerprint changes, so enabling this does not shrink existing files.
- One file, one key on writes: a file containing several keys is readable
  as long as the desired key is among them, but the resource refuses to
  rewrite a multi-key file that does not contain the desired key.
- A `homedir` outlives the run and doubles as a key store: a key already
  in it is exported without contacting `url` or `keyserver` at all, so a
  pre-populated homedir works on hosts without network access. Nothing
  refreshes such a key on its own - drop it from the homedir and run
  again. The directory is created with mode 0700 when missing, an
  existing one keeps its permissions, and the `delete` action only
  removes the keyring file. A run that finds no such directory says so
  with a warning before creating one: a homedir that is not there is as
  easily a typo in the recipe as a first run.
- Fetching never touches your homedir. Downloading, receiving and
  importing all happen in a throwaway one, and what your homedir is
  handed afterwards is the placed keyring itself: the same verified,
  `export-minimal` key that went into the file, and nothing else. A run
  that stops on the fingerprint or `user_id` assertion leaves it exactly
  as it was: uncreated if it was not there, and otherwise untouched. gpg
  initializes any homedir it is pointed at - it creates the store its
  configuration names, builds a trustdb, and starts keyboxd where that is
  the store - so the lookup deciding whether a fetch is needed is made
  over a throwaway copy of your keys, and your homedir is pointed at only
  once the key has been verified. Keys are found there whether they live
  in `pubring.kbx`, 1.4's `pubring.gpg`, or keyboxd's `public-keys.d`.
- Reading an already-placed keyring is a throwaway homedir too, so keys
  you keep in yours never end up in the file. A `gpg.conf` in it is
  ignored as well (`--no-options`): options like `armor` would otherwise
  decide what gets written.
- The keyring file is written after the homedir has been updated, so a
  target *inside* the homedir lands on whatever gpg keeps under that
  name. A path naming one of gpg's own files (`pubring.kbx`,
  `pubring.gpg`, `trustdb.gpg`, any `*.conf`, the agent sockets, ...) or
  anything inside one of its directories (`public-keys.d`,
  `private-keys-v1.d`, ...) stops the run; any other path in there works
  and is warned about once. Both paths are resolved before they are
  compared, so a symlink cannot present one of those as something else.
  Keep the keyring outside the homedir and the question does not arise.

## GnuPG versions

GnuPG 1.4.3 or newer, where `import-minimal` and `export-minimal` appeared.
The version is checked before every action, so an older `gpg` stops the run
by name instead of failing later as an unknown-option error; a version
string that cannot be read is left alone rather than refused.

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

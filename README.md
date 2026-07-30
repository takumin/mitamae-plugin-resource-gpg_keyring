# mitamae-plugin-resource-gpg_keyring

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

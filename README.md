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

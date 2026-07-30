test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# An already-placed ECC keyring, read rather than fetched. On a GnuPG
# without ECC support this is where the misleading "no valid user IDs"
# comes from, so the resource names the algorithm instead.
gpg_keyring File.join(test_dir, 'temporary', 'existing-ed25519.gpg') do
  fingerprint '177ACBBF0F0DF7E60E58ACD618DE04FD1CEFC6E4'
  user_id 'Ed25519 Key <ed25519@example.com>'
  url 'http://127.0.0.1:39418/ed25519.asc'
end

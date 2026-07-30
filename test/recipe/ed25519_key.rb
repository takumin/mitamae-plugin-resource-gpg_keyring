test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# ed25519 keyring: the other fixtures are RSA so that the suite can also
# run against GnuPG 1.4, and this one keeps the modern algorithm covered.
gpg_keyring File.join(test_dir, 'temporary', 'ed25519.gpg') do
  fingerprint '177ACBBF0F0DF7E60E58ACD618DE04FD1CEFC6E4'
  user_id 'Ed25519 Key <ed25519@example.com>'
  url 'http://127.0.0.1:39418/ed25519.asc'
end

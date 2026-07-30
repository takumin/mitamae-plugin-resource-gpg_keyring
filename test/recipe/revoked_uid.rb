test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# The keyring placed by the spec carries a revoked uid next to the valid
# one; the revoked uid must be ignored, so the run reports no change and
# leaves the file alone.
gpg_keyring File.join(test_dir, 'temporary', 'revoked-uid.gpg.asc') do
  fingerprint '828D52A36273EEC9DECAABFA69F9919E50A2FA6E'
  user_id 'Valid <valid@example.com>'
end

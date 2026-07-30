test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# The placed keyring does not carry this uid, so the run must stop
# before touching the file.
gpg_keyring File.join(test_dir, 'temporary', 'mismatch.gpg.asc') do
  fingerprint 'EB7799FC07E9E5BEF41905894072ADEA8961DFD8'
  user_id 'Wrong Person <wrong@example.com>'
end

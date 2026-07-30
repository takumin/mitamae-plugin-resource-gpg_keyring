test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# The placed keyring does not carry this uid, so the run must stop
# before touching the file.
gpg_keyring File.join(test_dir, 'temporary', 'mismatch.gpg.asc') do
  fingerprint '789ACEE7FE33FEACDF042B8BC0A90B87712D6C7F'
  user_id 'Wrong Person <wrong@example.com>'
end

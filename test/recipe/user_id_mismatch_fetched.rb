test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# The fetched key does not carry this uid; the run must stop after the
# download and before the target file is created.
gpg_keyring File.join(test_dir, 'temporary', 'verify-target.gpg.asc') do
  fingerprint '789ACEE7FE33FEACDF042B8BC0A90B87712D6C7F'
  user_id 'Wrong Person <wrong@example.com>'
  url "file://#{File.join(test_dir, 'fixture', 'valid-key.asc')}"
end

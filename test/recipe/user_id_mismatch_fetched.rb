test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# The fetched key does not carry this uid; the run must stop after the
# download and before the target file is created.
gpg_keyring File.join(test_dir, 'temporary', 'verify-target.gpg.asc') do
  fingerprint 'EB7799FC07E9E5BEF41905894072ADEA8961DFD8'
  user_id 'Wrong Person <wrong@example.com>'
  url "file://#{File.join(test_dir, 'fixture', 'valid-key.asc')}"
end

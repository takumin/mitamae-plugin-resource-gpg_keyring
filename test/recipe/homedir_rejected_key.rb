test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# The fetched key does not carry this uid, so the run stops on the
# assertion - with nothing written to the homedir named here.
gpg_keyring File.join(test_dir, 'temporary', 'homedir-rejected.gpg.asc') do
  fingerprint 'EB7799FC07E9E5BEF41905894072ADEA8961DFD8'
  user_id 'Wrong Person <wrong@example.com>'
  url "file://#{File.join(test_dir, 'fixture', 'valid-key.asc')}"
  homedir File.join(test_dir, 'temporary', 'gnupg')
end

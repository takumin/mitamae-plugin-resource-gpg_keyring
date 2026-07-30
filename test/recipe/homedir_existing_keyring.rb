test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# The keyring is already in place, so reading it must not reach for the
# homedir named here.
gpg_keyring File.join(test_dir, 'temporary', 'existing.gpg.asc') do
  fingerprint 'EB7799FC07E9E5BEF41905894072ADEA8961DFD8'
  user_id 'Valid <valid@example.com>'
  homedir File.join(test_dir, 'temporary', 'gnupg')
end

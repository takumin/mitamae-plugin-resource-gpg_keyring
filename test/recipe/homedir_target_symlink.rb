test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# The target goes through a symlink inside the homedir that leads to a
# directory gpg keeps, which the path as written does not say.
gpg_keyring File.join(test_dir, 'temporary', 'gnupg', 'keys', 'pubring.db') do
  fingerprint 'EB7799FC07E9E5BEF41905894072ADEA8961DFD8'
  user_id 'Valid <valid@example.com>'
  keyserver 'hkp://127.0.0.1:39418'
  homedir File.join(test_dir, 'temporary', 'gnupg')
end

test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# The target is the keyboxd database, one directory below the homedir.
gpg_keyring File.join(test_dir, 'temporary', 'gnupg', 'public-keys.d', 'pubring.db') do
  fingerprint 'EB7799FC07E9E5BEF41905894072ADEA8961DFD8'
  user_id 'Valid <valid@example.com>'
  keyserver 'hkp://127.0.0.1:39418'
  homedir File.join(test_dir, 'temporary', 'gnupg')
end

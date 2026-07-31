test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# The target reaches the homedir under another name, and the reserved
# directory it then names points out of the homedir again - so where the
# path leads and how it is written both miss what gpg is about to create.
gpg_keyring File.join(test_dir, 'temporary', 'alias', 'public-keys.d', 'pubring.db') do
  fingerprint 'EB7799FC07E9E5BEF41905894072ADEA8961DFD8'
  user_id 'Valid <valid@example.com>'
  keyserver 'hkp://127.0.0.1:39418'
  homedir File.join(test_dir, 'temporary', 'gnupg')
end

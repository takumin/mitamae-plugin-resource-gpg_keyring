test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# The homedir is named through a symlinked ancestor and does not exist
# yet, while the target names the same directory through the real one.
gpg_keyring File.join(test_dir, 'temporary', 'real', 'gnupg', 'pubring.kbx') do
  fingerprint 'EB7799FC07E9E5BEF41905894072ADEA8961DFD8'
  user_id 'Valid <valid@example.com>'
  keyserver 'hkp://127.0.0.1:39418'
  homedir File.join(test_dir, 'temporary', 'alias', 'gnupg')
end

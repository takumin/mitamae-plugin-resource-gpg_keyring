test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# The target is one of gpg's own directories rather than something under
# it, which leaves a plain file where gpg needs a directory.
gpg_keyring File.join(test_dir, 'temporary', 'gnupg', 'public-keys.d') do
  fingerprint 'EB7799FC07E9E5BEF41905894072ADEA8961DFD8'
  user_id 'Valid <valid@example.com>'
  keyserver 'hkp://127.0.0.1:39418'
  homedir File.join(test_dir, 'temporary', 'gnupg')
end

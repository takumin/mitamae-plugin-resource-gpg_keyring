test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# The lock gpg takes over its keybox. A keyring written there is read as a
# lock held by a process that does not exist, and gpg then refuses the
# keyring the lock is for.
gpg_keyring File.join(test_dir, 'temporary', 'gnupg', 'pubring.kbx.lock') do
  fingerprint 'EB7799FC07E9E5BEF41905894072ADEA8961DFD8'
  user_id 'Valid <valid@example.com>'
  keyserver 'hkp://127.0.0.1:39418'
  homedir File.join(test_dir, 'temporary', 'gnupg')
end

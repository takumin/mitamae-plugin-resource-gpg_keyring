test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# Dropping the `new/..` that nothing on disk can resolve uncovers `alias`,
# which is a symlink to where the target already is - and which the kernel
# follows as soon as `mkdir -p` creates `new`.
gpg_keyring File.join(test_dir, 'temporary', 'real', 'pubring.kbx') do
  fingerprint 'EB7799FC07E9E5BEF41905894072ADEA8961DFD8'
  user_id 'Valid <valid@example.com>'
  keyserver 'hkp://127.0.0.1:39418'
  homedir File.join(test_dir, 'temporary', 'h', 'new', '..', 'alias')
end

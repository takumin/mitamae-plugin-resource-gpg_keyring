test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# The homedir walks back out of a directory that is not there yet, so
# nothing on disk resolves the `..`: it is `mkdir -p` that creates `new`,
# after which gpg reads the homedir as the target's own directory.
gpg_keyring File.join(test_dir, 'temporary', 'gnupg', 'pubring.kbx') do
  fingerprint 'EB7799FC07E9E5BEF41905894072ADEA8961DFD8'
  user_id 'Valid <valid@example.com>'
  keyserver 'hkp://127.0.0.1:39418'
  homedir File.join(test_dir, 'temporary', 'gnupg', 'new', '..')
end

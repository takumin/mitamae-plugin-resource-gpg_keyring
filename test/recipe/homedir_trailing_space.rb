test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# The homedir's name ends in a space, and `pwd` prints that space right
# before its newline: take both off and the homedir is a directory the
# target no longer sits in.
gpg_keyring File.join(test_dir, 'temporary', 'gnupg ', 'pubring.kbx') do
  fingerprint 'EB7799FC07E9E5BEF41905894072ADEA8961DFD8'
  user_id 'Valid <valid@example.com>'
  keyserver 'hkp://127.0.0.1:39418'
  homedir File.join(test_dir, 'temporary', 'gnupg ')
end

test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# The homedir's name ends in a newline, which is a byte a command
# substitution takes off: resolved through one, the homedir becomes a
# different directory that the target no longer sits in.
gpg_keyring File.join(test_dir, 'temporary', "gnupg\n", 'pubring.kbx') do
  fingerprint 'EB7799FC07E9E5BEF41905894072ADEA8961DFD8'
  user_id 'Valid <valid@example.com>'
  keyserver 'hkp://127.0.0.1:39418'
  homedir File.join(test_dir, 'temporary', "gnupg\n")
end

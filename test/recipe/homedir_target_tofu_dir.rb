test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# The split TOFU database is a directory, and the name it lives under is
# reserved even where the running gpg keeps the flat `tofu.db` instead: a
# keyring written there is a plain file in a directory's place.
gpg_keyring File.join(test_dir, 'temporary', 'gnupg', 'tofu.d') do
  fingerprint 'EB7799FC07E9E5BEF41905894072ADEA8961DFD8'
  user_id 'Valid <valid@example.com>'
  keyserver 'hkp://127.0.0.1:39418'
  homedir File.join(test_dir, 'temporary', 'gnupg')
end

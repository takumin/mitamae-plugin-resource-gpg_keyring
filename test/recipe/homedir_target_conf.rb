test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# keyboxd reads this the way gpg reads gpg.conf, so the keyring cannot be
# it either.
gpg_keyring File.join(test_dir, 'temporary', 'gnupg', 'keyboxd.conf') do
  fingerprint 'EB7799FC07E9E5BEF41905894072ADEA8961DFD8'
  user_id 'Valid <valid@example.com>'
  keyserver 'hkp://127.0.0.1:39418'
  homedir File.join(test_dir, 'temporary', 'gnupg')
end

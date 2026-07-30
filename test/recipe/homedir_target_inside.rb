test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# The keyring sits inside the homedir under a name gpg does not use: it
# works, and the run says so.
gpg_keyring File.join(test_dir, 'temporary', 'gnupg', 'inside.gpg') do
  fingerprint 'EB7799FC07E9E5BEF41905894072ADEA8961DFD8'
  user_id 'Valid <valid@example.com>'
  keyserver 'hkp://127.0.0.1:39418'
  homedir File.join(test_dir, 'temporary', 'gnupg')
end

test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# The homedir already holds the key, so nothing is fetched: port 1 on
# localhost refuses immediately and would fail the run otherwise.
gpg_keyring File.join(test_dir, 'temporary', 'homedir-offline.gpg.asc') do
  fingerprint 'EB7799FC07E9E5BEF41905894072ADEA8961DFD8'
  user_id 'Valid <valid@example.com>'
  keyserver 'hkp://127.0.0.1:1'
  homedir File.join(test_dir, 'temporary', 'gnupg')
end

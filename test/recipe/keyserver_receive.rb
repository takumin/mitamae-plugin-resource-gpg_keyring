test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# keyserver download keyring: received from the local HKP server started
# by the spec suite.
gpg_keyring File.join(test_dir, 'temporary', 'keyserver.gpg.asc') do
  fingerprint 'EB7799FC07E9E5BEF41905894072ADEA8961DFD8'
  user_id 'Valid <valid@example.com>'
  keyserver 'hkp://127.0.0.1:39418'
end

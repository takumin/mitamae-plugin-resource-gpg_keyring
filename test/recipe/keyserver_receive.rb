test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# keyserver download keyring: received from the local HKP server started
# by the spec suite.
gpg_keyring File.join(test_dir, 'temporary', 'keyserver.gpg.asc') do
  fingerprint '789ACEE7FE33FEACDF042B8BC0A90B87712D6C7F'
  user_id 'Valid <valid@example.com>'
  keyserver 'hkp://127.0.0.1:39418'
end

test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# url download keyring: fetched from the local fixture server started by
# the spec suite.
gpg_keyring File.join(test_dir, 'temporary', 'url-download.gpg.asc') do
  fingerprint 'EB7799FC07E9E5BEF41905894072ADEA8961DFD8'
  user_id 'Valid <valid@example.com>'
  url 'http://127.0.0.1:39418/valid-key.asc'
end

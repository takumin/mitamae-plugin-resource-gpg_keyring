test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# url download keyring: fetched from the local fixture server started by
# the spec suite.
gpg_keyring File.join(test_dir, 'temporary', 'url-download.gpg.asc') do
  fingerprint '789ACEE7FE33FEACDF042B8BC0A90B87712D6C7F'
  user_id 'Valid <valid@example.com>'
  url 'http://127.0.0.1:39418/valid-key.asc'
end

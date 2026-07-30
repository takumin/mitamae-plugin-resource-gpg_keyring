test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# binary download keyring: a .gpg target is exported in binary form.
gpg_keyring File.join(test_dir, 'temporary', 'url-download.gpg') do
  fingerprint '789ACEE7FE33FEACDF042B8BC0A90B87712D6C7F'
  user_id 'Valid <valid@example.com>'
  url 'http://127.0.0.1:39418/valid-key.asc'
end

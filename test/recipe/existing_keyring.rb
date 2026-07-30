test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# exists keyring
gpg_keyring File.join(test_dir, 'temporary', 'existing.gpg.asc') do
  fingerprint '789ACEE7FE33FEACDF042B8BC0A90B87712D6C7F'
  user_id 'Valid <valid@example.com>'
end

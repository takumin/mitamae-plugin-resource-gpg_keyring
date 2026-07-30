test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# canonical keyring
gpg_keyring File.join(test_dir, 'temporary', 'existing.gpg.asc') do
  fingerprint '0x789ACEE7FE33FEACDF042B8BC0A90B87712D6C7F'
  user_id 'Valid <valid@example.com>'
end

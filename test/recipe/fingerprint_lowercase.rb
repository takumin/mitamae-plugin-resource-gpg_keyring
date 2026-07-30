test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# lower case keyring
gpg_keyring File.join(test_dir, 'temporary', 'existing.gpg.asc') do
  fingerprint '789acee7fe33feacdf042b8bc0a90b87712d6c7f'
  user_id 'Valid <valid@example.com>'
end

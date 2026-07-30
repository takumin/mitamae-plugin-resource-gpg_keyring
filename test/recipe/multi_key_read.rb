test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# The file holds two keys; as long as the desired key is one of them the
# resource reads it and leaves the file alone.
gpg_keyring File.join(test_dir, 'temporary', 'multi.gpg.asc') do
  fingerprint '04DBB5F22336D36116EF51E63A42CEC5EF02FC27'
  user_id 'First Key <first@example.com>'
end

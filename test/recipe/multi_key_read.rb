test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# The file holds two keys; as long as the desired key is one of them the
# resource reads it and leaves the file alone.
gpg_keyring File.join(test_dir, 'temporary', 'multi.gpg.asc') do
  fingerprint '038568CB42AB4FF156F0E32AD9DA25B18F1DD5E4'
  user_id 'First Key <first@example.com>'
end

test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# canonical keyring
gpg_keyring File.join(test_dir, 'temporary', 'existing.gpg.asc') do
  fingerprint '0xEB7799FC07E9E5BEF41905894072ADEA8961DFD8'
  user_id 'Valid <valid@example.com>'
end

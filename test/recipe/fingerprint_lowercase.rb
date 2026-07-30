test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# lower case keyring
gpg_keyring File.join(test_dir, 'temporary', 'existing.gpg.asc') do
  fingerprint 'eb7799fc07e9e5bef41905894072adea8961dfd8'
  user_id 'Valid <valid@example.com>'
end

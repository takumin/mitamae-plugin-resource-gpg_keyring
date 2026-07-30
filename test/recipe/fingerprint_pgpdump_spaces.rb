test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# pgpdump space keyring
gpg_keyring File.join(test_dir, 'temporary', 'existing.gpg.asc') do
  fingerprint 'eb 77 99 fc 07 e9 e5 be f4 19 05 89 40 72 ad ea 89 61 df d8'
  user_id 'Valid <valid@example.com>'
end

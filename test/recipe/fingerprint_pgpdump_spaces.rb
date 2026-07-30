test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# pgpdump space keyring
gpg_keyring File.join(test_dir, 'temporary', 'existing.gpg.asc') do
  fingerprint '78 9a ce e7 fe 33 fe ac df 04 2b 8b c0 a9 0b 87 71 2d 6c 7f'
  user_id 'Valid <valid@example.com>'
end

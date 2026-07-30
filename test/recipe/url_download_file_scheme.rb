test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# file url download keyring: same pipeline as the https cases, but kept
# runnable offline.
gpg_keyring File.join(test_dir, 'temporary', 'file-url.gpg.asc') do
  fingerprint '789ACEE7FE33FEACDF042B8BC0A90B87712D6C7F'
  user_id 'Valid <valid@example.com>'
  url "file://#{File.join(test_dir, 'fixture', 'valid-key.asc')}"
end

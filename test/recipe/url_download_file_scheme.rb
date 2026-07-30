test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# file url download keyring: same pipeline as the https cases, but kept
# runnable offline.
gpg_keyring File.join(test_dir, 'temporary', 'file-url.gpg.asc') do
  fingerprint 'EB7799FC07E9E5BEF41905894072ADEA8961DFD8'
  user_id 'Valid <valid@example.com>'
  url "file://#{File.join(test_dir, 'fixture', 'valid-key.asc')}"
end

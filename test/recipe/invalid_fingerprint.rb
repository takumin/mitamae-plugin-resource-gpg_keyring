test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# A fingerprint that does not normalize to 40 hex digits must abort the run
# before touching the target file.
gpg_keyring File.join(test_dir, 'temporary', 'never-created.gpg.asc') do
  fingerprint 'DEADBEEF'
end

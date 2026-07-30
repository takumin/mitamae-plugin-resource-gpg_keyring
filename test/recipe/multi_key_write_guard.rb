test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# The fingerprint matches neither key in the file; a re-fetch would
# overwrite the file and drop both keys, so the run must stop instead.
gpg_keyring File.join(test_dir, 'temporary', 'multi.gpg.asc') do
  fingerprint '0000000000000000000000000000000000000000'
end

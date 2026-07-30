test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# Deleting an already-absent keyring is a no-op and must not fetch
# anything.
gpg_keyring File.join(test_dir, 'temporary', 'missing.gpg.asc') do
  action :delete
  fingerprint '0000000000000000000000000000000000000000'
end

test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# A binary keyring exported out of a homedir the caller also configures.
# Port 1 on localhost refuses immediately, so the export has to come from
# the homedir rather than from a fetch.
gpg_keyring File.join(test_dir, 'temporary', 'homedir.gpg') do
  fingerprint 'EB7799FC07E9E5BEF41905894072ADEA8961DFD8'
  user_id 'Valid <valid@example.com>'
  keyserver 'hkp://127.0.0.1:1'
  homedir File.join(test_dir, 'temporary', 'gnupg')
end

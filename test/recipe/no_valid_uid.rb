test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# All uids of the placed key are revoked, so a requested user_id cannot
# be verified and the run must stop with the dedicated message.
gpg_keyring File.join(test_dir, 'temporary', 'no-valid-uid.gpg.asc') do
  fingerprint 'E4D03F8C907F170FBB90AB69124B9B5D558ED8FC'
  user_id 'Valid <valid@example.com>'
end

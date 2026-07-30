test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# All uids of the placed key are revoked, so a requested user_id cannot
# be verified and the run must stop with the dedicated message.
gpg_keyring File.join(test_dir, 'temporary', 'no-valid-uid.gpg.asc') do
  fingerprint 'FD4E60562617EA009641093DB77E4EDBFA1A1415'
  user_id 'Valid <valid@example.com>'
end

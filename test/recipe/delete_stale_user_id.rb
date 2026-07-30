test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# Deletion must not be blocked by the user_id assertion: every uid of the
# placed key is revoked, yet the file must still be removable.
gpg_keyring File.join(test_dir, 'temporary', 'obsolete.gpg.asc') do
  action :delete
  fingerprint 'FD4E60562617EA009641093DB77E4EDBFA1A1415'
  user_id 'Valid <valid@example.com>'
end

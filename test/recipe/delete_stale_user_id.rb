test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# Deletion must not be blocked by the user_id assertion: every uid of the
# placed key is revoked, yet the file must still be removable.
gpg_keyring File.join(test_dir, 'temporary', 'obsolete.gpg.asc') do
  action :delete
  fingerprint 'E4D03F8C907F170FBB90AB69124B9B5D558ED8FC'
  user_id 'Valid <valid@example.com>'
end

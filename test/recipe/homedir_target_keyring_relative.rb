# Same collision as homedir_target_keyring, written so that the two paths
# do not match as strings. mitamae runs with the repository as its working
# directory, so both resolve under test/temporary/gnupg.
gpg_keyring 'test/temporary/gnupg/pubring.kbx' do
  fingerprint 'EB7799FC07E9E5BEF41905894072ADEA8961DFD8'
  user_id 'Valid <valid@example.com>'
  keyserver 'hkp://127.0.0.1:39418'
  homedir './test/temporary/../temporary/gnupg'
end

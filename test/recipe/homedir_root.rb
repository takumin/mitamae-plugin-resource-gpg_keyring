# A homedir of `/` is still a homedir: the keybox gpg would keep in it is
# /pubring.kbx, and the run has to stop before anything is written.
gpg_keyring '/pubring.kbx' do
  fingerprint 'EB7799FC07E9E5BEF41905894072ADEA8961DFD8'
  user_id 'Valid <valid@example.com>'
  keyserver 'hkp://127.0.0.1:39418'
  homedir '/'
end

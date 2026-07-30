test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# Without user_id an empty valid-uid set is a normal state
# (keys.openpgp.org serves unverified keys without user ids), so the
# fingerprint-only recipe must pass and leave the file alone.
gpg_keyring File.join(test_dir, 'temporary', 'no-valid-uid.gpg.asc') do
  fingerprint 'E4D03F8C907F170FBB90AB69124B9B5D558ED8FC'
end

test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# gpg renames a store to `<name>~` before rewriting it, so the backup is
# as much gpg's as the store it belongs to. 1.4's secret keyring here.
gpg_keyring File.join(test_dir, 'temporary', 'gnupg', 'secring.gpg~') do
  fingerprint 'EB7799FC07E9E5BEF41905894072ADEA8961DFD8'
  user_id 'Valid <valid@example.com>'
  keyserver 'hkp://127.0.0.1:39418'
  homedir File.join(test_dir, 'temporary', 'gnupg')
end

test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# 06F2... is a sub key of the placed keyring; treating it as a plain
# mismatch would re-fetch forever, so it must fail with its own message.
gpg_keyring File.join(test_dir, 'temporary', 'with-subkey.gpg.asc') do
  fingerprint '06F21A635790E1E30836CC181F2B92E60917A236'
end

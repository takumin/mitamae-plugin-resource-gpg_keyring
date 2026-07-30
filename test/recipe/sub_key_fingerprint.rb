test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# 06F2... is a sub key of the placed keyring; treating it as a plain
# mismatch would re-fetch forever, so it must fail with its own message.
gpg_keyring File.join(test_dir, 'temporary', 'with-subkey.gpg.asc') do
  fingerprint '44E0885959F52DA7C4FEA5D8CF9505A6B465FE42'
end

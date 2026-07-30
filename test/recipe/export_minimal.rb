test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# The committed fixture carries a third-party signature; the placed
# keyring must contain only the key and its self-signature.
gpg_keyring File.join(test_dir, 'temporary', 'minimal.gpg.asc') do
  fingerprint '82C25A3D16117FD205D3E1C1F680CC77CE8E487A'
  url "file://#{File.join(test_dir, 'fixture', 'third-party-signed.asc')}"
end

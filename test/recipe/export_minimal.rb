test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# The committed fixture carries a third-party signature; the placed
# keyring must contain only the key and its self-signature.
gpg_keyring File.join(test_dir, 'temporary', 'minimal.gpg.asc') do
  fingerprint '4E813E3616555FBA767A6CD831F4B52B27128416'
  url "file://#{File.join(test_dir, 'fixture', 'third-party-signed.asc')}"
end

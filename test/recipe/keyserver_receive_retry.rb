test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# An unreachable keyserver is retried with backoff before the run fails.
# Port 1 on localhost refuses immediately, so the case stays offline.
gpg_keyring File.join(test_dir, 'temporary', 'unreachable.gpg.asc') do
  fingerprint 'F487F0CB3B38FC5CE3512CC4F18EC5EF947FFAD2'
  keyserver 'hkp://127.0.0.1:1'
end

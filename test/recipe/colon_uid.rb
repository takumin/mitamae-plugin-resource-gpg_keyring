test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# The uid contains a colon, which gpg escapes as \x3a in colon-format
# listings; the natural string given here must still match.
gpg_keyring File.join(test_dir, 'temporary', 'colon-uid.gpg.asc') do
  fingerprint 'F11304455DC32D8D29B6955EE33C60CAC2205B2C'
  user_id 'Colon: User <colon@example.com>'
end

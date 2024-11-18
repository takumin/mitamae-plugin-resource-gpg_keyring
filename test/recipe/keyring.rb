test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# exists keyring
gpg_keyring File.join(test_dir, 'keyring', 'takumin.gpg.asc') do
  fingerprint 'F487F0CB3B38FC5CE3512CC4F18EC5EF947FFAD2'
  user_id 'Takumi Takahashi <takumiiinn@gmail.com>'
  url 'https://github.com/takumin.gpg'
end

# lower case keyring
gpg_keyring File.join(test_dir, 'keyring', 'takumin.gpg.asc') do
  fingerprint 'f487f0cb3b38fc5ce3512cc4f18ec5ef947ffad2'
  user_id 'Takumi Takahashi <takumiiinn@gmail.com>'
  url 'https://github.com/takumin.gpg'
end

# canonical keyring
gpg_keyring File.join(test_dir, 'keyring', 'takumin.gpg.asc') do
  fingerprint '0xF487F0CB3B38FC5CE3512CC4F18EC5EF947FFAD2'
  user_id 'Takumi Takahashi <takumiiinn@gmail.com>'
  url 'https://github.com/takumin.gpg'
end

# pgpdump space keyring
gpg_keyring File.join(test_dir, 'keyring', 'takumin.gpg.asc') do
  fingerprint 'f4 87 f0 cb 3b 38 fc 5c e3 51 2c c4 f1 8e c5 ef 94 7f fa d2'
  user_id 'Takumi Takahashi <takumiiinn@gmail.com>'
  url 'https://github.com/takumin.gpg'
end

# url download keyring
gpg_keyring File.join(test_dir, 'temporary', 'github-takumin.gpg.asc') do
  fingerprint 'F487F0CB3B38FC5CE3512CC4F18EC5EF947FFAD2'
  user_id 'Takumi Takahashi <takumiiinn@gmail.com>'
  url 'https://github.com/takumin.gpg'
end

# binary download keyring
gpg_keyring File.join(test_dir, 'temporary', 'github-takumin.gpg') do
  fingerprint 'F487F0CB3B38FC5CE3512CC4F18EC5EF947FFAD2'
  user_id 'Takumi Takahashi <takumiiinn@gmail.com>'
  url 'https://github.com/takumin.gpg'
end

# keyserver download keyring
gpg_keyring File.join(test_dir, 'temporary', 'keyserver-takumin.gpg.asc') do
  fingerprint 'F487F0CB3B38FC5CE3512CC4F18EC5EF947FFAD2'
  user_id 'Takumi Takahashi <takumiiinn@gmail.com>'
  keyserver 'hkps://keys.openpgp.org'
end

# ubuntu keyserver download keyring
gpg_keyring File.join(test_dir, 'temporary', 'ubuntu-keyserver-takumin.gpg.asc') do
  fingerprint 'F487F0CB3B38FC5CE3512CC4F18EC5EF947FFAD2'
  user_id 'Takumi Takahashi <takumiiinn@gmail.com>'
  keyserver 'hkps://keyserver.ubuntu.com'
end

test_dir = File.expand_path(File.dirname(File.dirname(__FILE__)))

# exists keyring
gpg_keyring File.join(test_dir, 'keyring', 'takumin.gpg.asc') do
  fingerprint 'F487F0CB3B38FC5CE3512CC4F18EC5EF947FFAD2'
  user_id 'Takumi Takahashi <takumiiinn@gmail.com>'
  url 'https://github.com/takumin.gpg'
end

# url download keyring
gpg_keyring File.join(test_dir, 'temporary', 'github-takumin.gpg.asc') do
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

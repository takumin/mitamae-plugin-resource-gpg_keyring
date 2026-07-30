RSpec.describe 'user_id assertion' do
  # Places the fixture whose only uid is revoked (0 valid uids), mimicking
  # a key stripped down the way keys.openpgp.org serves unverified keys.
  def place_no_valid_uid_keyring(keyring)
    FileUtils.cp(fixture('no-valid-uid.asc'), keyring)

    uid_lines = gpg_show_keys(keyring).lines.grep(/^uid:/)
    expect(uid_lines.size).to eq(1)
    expect(uid_lines.first).to start_with('uid:r:')
  end

  it 'matches a uid that gpg escapes in colon-format listings' do
    keyring = temporary('colon-uid.gpg.asc')
    FileUtils.cp(fixture('colon-uid.asc'), keyring)

    # The colon in the uid must actually be escaped in the listing,
    # otherwise this example proves nothing.
    expect(gpg_show_keys(keyring)).to include('Colon\x3a User')

    run = run_mitamae('colon_uid')
    expect_mitamae_success(run)
    expect(run.log).not_to include('will change from')
    expect(File.binread(keyring)).to eq(File.binread(fixture('colon-uid.asc')))
  end

  it 'stops when the placed keyring does not carry the asserted uid' do
    keyring = temporary('mismatch.gpg.asc')
    FileUtils.cp(fixture('valid-key.asc'), keyring)

    run = run_mitamae('user_id_mismatch')
    expect_mitamae_failure(run, /gpg user_id verification failed: expected/)
    # The error lists what the key actually carries.
    expect(run.log).to include('Valid <valid@example.com>')
    expect(File.binread(keyring)).to eq(File.binread(fixture('valid-key.asc')))
  end

  it 'stops after the fetch when the fetched key does not carry the asserted uid' do
    run = run_mitamae('user_id_mismatch_fetched')
    expect_mitamae_failure(run, /gpg user_id verification failed: expected/)
    expect(run.log).to include('Valid <valid@example.com>')
    expect(File.exist?(temporary('verify-target.gpg.asc'))).to be(false)
  end

  it 'stops with a dedicated message when no valid uid remains' do
    keyring = temporary('no-valid-uid.gpg.asc')
    place_no_valid_uid_keyring(keyring)

    run = run_mitamae('no_valid_uid')
    expect_mitamae_failure(run, /no valid user id/)
    expect(File.binread(keyring)).to eq(File.binread(fixture('no-valid-uid.asc')))
  end

  it 'passes without user_id even when no valid uid remains' do
    keyring = temporary('no-valid-uid.gpg.asc')
    place_no_valid_uid_keyring(keyring)

    run = run_mitamae('without_user_id')
    expect_mitamae_success(run)
    expect(run.log).not_to include('will change from')
    expect(File.binread(keyring)).to eq(File.binread(fixture('no-valid-uid.asc')))
  end
end

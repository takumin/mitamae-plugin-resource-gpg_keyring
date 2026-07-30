RSpec.describe 'delete action' do
  it 'removes the keyring even when the uid assertion no longer holds' do
    keyring = temporary('obsolete.gpg.asc')
    FileUtils.cp(fixture('no-valid-uid.asc'), keyring)

    run = run_mitamae('delete_stale_user_id')
    expect_mitamae_success(run)
    expect(File.exist?(keyring)).to be(false)
  end

  it 'does nothing and fetches nothing when the target is already absent' do
    run = run_mitamae('delete_missing')
    expect_mitamae_success(run)
    expect(File.exist?(temporary('missing.gpg.asc'))).to be(false)
    expect(run.log).not_to include('gpg download')
    expect(run.log).not_to include('--receive-keys')
  end
end

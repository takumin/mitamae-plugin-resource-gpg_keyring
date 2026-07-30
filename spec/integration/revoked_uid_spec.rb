RSpec.describe 'revoked uid handling' do
  it 'ignores the revoked uid and reports no change' do
    keyring = temporary('revoked-uid.gpg.asc')
    FileUtils.cp(fixture('revoked-uid.asc'), keyring)

    # The revoked uid must be the last uid line: that is the line the old
    # flat parser picked up, so this example regresses loudly if revoked
    # uids stop being excluded. The '-' expectation pins unknown validity
    # as valid (placed files never have a trustdb).
    uid_lines = gpg_show_keys(keyring).lines.grep(/^uid:/)
    expect(uid_lines.first).to start_with('uid:-:')
    expect(uid_lines.last).to start_with('uid:r:')

    run = run_mitamae('revoked_uid')
    expect_mitamae_success(run)
    expect(run.log).not_to include('will change from')
    expect(File.binread(keyring)).to eq(File.binread(fixture('revoked-uid.asc')))
  end
end

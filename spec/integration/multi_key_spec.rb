RSpec.describe 'multiple pub keys' do
  def place_multi_keyring(keyring)
    FileUtils.cp(fixture('multi-key.asc'), keyring)
    expect(gpg_show_keys(keyring).lines.grep(/^pub:/).size).to eq(2)
  end

  it 'reads a multi-key file when the desired key is among them' do
    keyring = temporary('multi.gpg.asc')
    place_multi_keyring(keyring)

    run = run_mitamae('multi_key_read')
    expect_mitamae_success(run)
    expect(run.log).not_to include('will change from')
    # The foreign key is surfaced in the debug log.
    expect(run.log).to include('keyring also contains other keys')
    expect(File.binread(keyring)).to eq(File.binread(fixture('multi-key.asc')))
  end

  it 'stops with a dedicated message when the fingerprint matches a sub key' do
    keyring = temporary('with-subkey.gpg.asc')
    FileUtils.cp(fixture('with-subkey.asc'), keyring)
    expect(gpg_show_keys(keyring).lines.grep(/^sub:/).size).to eq(1)

    run = run_mitamae('sub_key_fingerprint')
    expect_mitamae_failure(run, /is a sub key of 46EACE42ED8B71D8EBD2939486BA84F24F9235F0/)
    expect(File.binread(keyring)).to eq(File.binread(fixture('with-subkey.asc')))
  end

  it 'refuses to rewrite a multi-key file that lacks the desired key' do
    keyring = temporary('multi.gpg.asc')
    place_multi_keyring(keyring)

    run = run_mitamae('multi_key_write_guard')
    expect_mitamae_failure(run, /refusing to rewrite the file/)
    expect(File.binread(keyring)).to eq(File.binread(fixture('multi-key.asc')))
  end
end

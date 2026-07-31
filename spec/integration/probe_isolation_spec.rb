RSpec.describe 'gpg probes' do
  # Every example in the suite already asserts that HOME comes out
  # untouched (see spec_helper's after hook), which is the guarantee
  # itself. What is left to pin down here is that the two probes are
  # reached at all under the flags they are supposed to carry - the
  # --list-packets one is unreachable on a gpg that has ECC, so on the
  # main matrix it takes a binary that says it has none.

  # A banner new enough to pass the version check and naming no ECC
  # algorithm, which is what a GnuPG 1.4 looks like from here.
  NO_ECC_BANNER = 'echo "gpg (GnuPG) 2.4.4"'.freeze

  it 'runs the version probe once, without a gpg.conf and without a homedir' do
    keyring = temporary('existing.gpg.asc')
    FileUtils.cp(fixture('valid-key.asc'), keyring)

    run = run_mitamae('existing_keyring')
    expect_mitamae_success(run)

    versions = run.log.scan(/Executing `gpg[^`]*--version`/)
    # --no-options because a caller's gpg.conf must not get a say in the
    # answer; no --homedir because the probe reads no keyring and creates
    # nothing, so there is no state a homedir would have to keep out of
    # the way.
    expect(versions).to eq(['Executing `gpg --no-options --version`'])
  end

  it 'runs the packet dump in a homedir of the run, not the caller\'s' do
    # An unreadable keyring is the one way to fail an import on a gpg
    # that has every algorithm: the resource then asks what algorithm the
    # key uses, which is the probe under test. It answers nothing here
    # (there is no key to read), so the failure stays the plain one.
    keyring = temporary('existing.gpg.asc')
    File.write(keyring, "not a key at all\n")

    with_gpg_stub(NO_ECC_BANNER) do
      run = run_mitamae('existing_keyring')
      # Nothing to add to the import failure, so it keeps its original
      # type - which mitamae reports as the bare "Failed." (see
      # raise_command_failure).
      expect_mitamae_failure(run, /gpg_keyring\[#{Regexp.escape(keyring)}\] Failed\./)
      expect(run.log).to match(/Executing `gpg --homedir \S+ --no-options .*--list-packets/)
    end
  end
end

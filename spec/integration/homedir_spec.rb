RSpec.describe 'homedir' do
  HOMEDIR_KEY_FINGERPRINT = 'EB7799FC07E9E5BEF41905894072ADEA8961DFD8'.freeze

  it 'keeps the received key in the homedir named by the recipe' do
    run = run_mitamae('homedir_keyserver')
    expect_mitamae_success(run)

    expect(fingerprint_of(temporary('homedir.gpg.asc'))).to eq(HOMEDIR_KEY_FINGERPRINT)
    expect(homedir_fingerprints(gpg_homedir)).to include(HOMEDIR_KEY_FINGERPRINT)
  end

  # A homedir that is not there is as easily a typo as a first run, so the
  # run says which one it is looking at before it creates anything.
  it 'warns when the homedir named by the recipe does not exist' do
    run = run_mitamae('homedir_keyserver')
    expect_mitamae_success(run)
    expect(run.log).to match(/WARN.*gpg homedir does not exist: #{Regexp.escape(gpg_homedir)}/)
  end

  it 'says nothing about a homedir that is already there' do
    import_into_homedir(gpg_homedir, fixture('valid-key.asc'))

    run = run_mitamae('homedir_offline')
    expect_mitamae_success(run)
    expect(run.log).not_to include('gpg homedir does not exist')
  end

  # Port 1 on localhost refuses immediately, so a fetch would fail the run:
  # success proves the key came out of the homedir.
  it 'places the keyring from the homedir without contacting the keyserver' do
    import_into_homedir(gpg_homedir, fixture('valid-key.asc'))

    run = run_mitamae('homedir_offline')
    expect_mitamae_success(run)

    expect(fingerprint_of(temporary('homedir-offline.gpg.asc'))).to eq(HOMEDIR_KEY_FINGERPRINT)
    expect(run.log).not_to include('--recv-keys')
  end

  it 'exports only the pinned key from a homedir that holds others' do
    import_into_homedir(gpg_homedir, fixture('valid-key.asc'), fixture('multi-key.asc'))

    run = run_mitamae('homedir_offline')
    expect_mitamae_success(run)

    keyring = temporary('homedir-offline.gpg.asc')
    expect(gpg_show_keys(keyring).scan(/^fpr:{9}([0-9A-F]{40}):/).flatten).to eq([HOMEDIR_KEY_FINGERPRINT])
  end

  # A gpg.conf carrying `armor` would otherwise turn the binary export into
  # an armored one, so this pins the config isolation the resource relies on.
  it 'ignores a gpg.conf the caller left in the homedir' do
    import_into_homedir(gpg_homedir, fixture('valid-key.asc'))
    File.write(File.join(gpg_homedir, 'gpg.conf'), "armor\n")

    run = run_mitamae('homedir_binary')
    expect_mitamae_success(run)

    expect(armored?(temporary('homedir.gpg'))).to be(false)
    expect(File.read(File.join(gpg_homedir, 'gpg.conf'))).to eq("armor\n")
  end

  it 'leaves the homedir alone when the placed keyring is already correct' do
    keyring = temporary('existing.gpg.asc')
    FileUtils.cp(fixture('valid-key.asc'), keyring)

    run = run_mitamae('homedir_existing_keyring')
    expect_mitamae_success(run)

    expect(File.binread(keyring)).to eq(File.binread(fixture('valid-key.asc')))
    expect(File.exist?(gpg_homedir)).to be(false)
  end

  # The keyring is written after the homedir import, so a target inside
  # the homedir lands on whatever gpg keeps under that name.
  it 'refuses a keyring aimed at a file gpg keeps in the homedir' do
    import_into_homedir(gpg_homedir, fixture('valid-key.asc'))

    run = run_mitamae('homedir_target_keyring')
    expect_mitamae_failure(run, /is a file gpg keeps in its homedir/)

    expect(homedir_fingerprints(gpg_homedir)).to eq([HOMEDIR_KEY_FINGERPRINT])
  end

  # The two paths are the same directory spelled differently, which a
  # string comparison would let through.
  it 'refuses the same collision when the paths are spelled differently' do
    import_into_homedir(gpg_homedir, fixture('valid-key.asc'))

    run = run_mitamae('homedir_target_keyring_relative')
    expect_mitamae_failure(run, /is a file gpg keeps in its homedir/)

    expect(homedir_fingerprints(gpg_homedir)).to eq([HOMEDIR_KEY_FINGERPRINT])
  end

  # Spelled differently again, but with the difference in the part of the
  # homedir that does not exist yet: nothing on disk resolves that `..`,
  # and the `mkdir -p` that does comes after the check.
  it 'refuses the same collision when the homedir ends in a dot segment' do
    run = run_mitamae('homedir_dot_segment')
    expect_mitamae_failure(run, /is a file gpg keeps in its homedir/)

    expect(File.exist?(gpg_homedir)).to be(false)
  end

  it 'refuses a keyring aimed inside a directory gpg keeps in the homedir' do
    run = run_mitamae('homedir_target_keyboxd')
    expect_mitamae_failure(run, /is inside public-keys\.d, which gpg keeps in its homedir/)

    expect(File.exist?(gpg_homedir)).to be(false)
  end

  # The path as written says `keys/pubring.db`, which no list covers; where
  # it leads is keyboxd's database.
  it 'refuses a keyring aimed through a symlink to one of those directories' do
    FileUtils.mkdir_p(File.join(gpg_homedir, 'public-keys.d'))
    FileUtils.chmod(0o700, gpg_homedir)
    File.symlink('public-keys.d', File.join(gpg_homedir, 'keys'))
    File.write(File.join(gpg_homedir, 'public-keys.d', 'pubring.db'), 'keyboxd')

    run = run_mitamae('homedir_target_symlink')
    expect_mitamae_failure(run, /is inside public-keys\.d, which gpg keeps in its homedir/)

    expect(File.read(File.join(gpg_homedir, 'public-keys.d', 'pubring.db'))).to eq('keyboxd')
  end

  # A write follows the whole chain, so the guard has to as well.
  it 'refuses a keyring aimed through a chain of symlinks' do
    import_into_homedir(gpg_homedir, fixture('valid-key.asc'))
    # Whichever of the two the gpg under test wrote: 2.x's keybox, or the
    # keyring 1.4 leaves behind.
    keyring = %w[pubring.kbx pubring.gpg].detect { |name| File.exist?(File.join(gpg_homedir, name)) }
    before = File.binread(File.join(gpg_homedir, keyring))
    File.symlink(keyring, File.join(gpg_homedir, 'alias'))
    File.symlink('alias', File.join(gpg_homedir, 'out'))

    run = run_mitamae('homedir_target_symlink_chain')
    expect_mitamae_failure(run, /is a file gpg keeps in its homedir/)

    expect(File.binread(File.join(gpg_homedir, keyring))).to eq(before)
  end

  # The link leads to a directory gpg has not created yet, so there is
  # nothing on disk to resolve - and the import is what creates it.
  it 'refuses a keyring aimed through a symlink that dangles into one' do
    FileUtils.mkdir_p(gpg_homedir)
    FileUtils.chmod(0o700, gpg_homedir)
    File.symlink('public-keys.d/pubring.db', File.join(gpg_homedir, 'out'))

    run = run_mitamae('homedir_target_symlink_chain')
    expect_mitamae_failure(run, /is inside public-keys\.d, which gpg keeps in its homedir/)

    expect(File.exist?(File.join(gpg_homedir, 'public-keys.d'))).to be(false)
  end

  # Same link, but as the target's parent rather than the target: the leaf
  # loop never looks at it, so resolving has to happen on the way down.
  it 'refuses a keyring under a symlinked directory that does not exist yet' do
    FileUtils.mkdir_p(gpg_homedir)
    FileUtils.chmod(0o700, gpg_homedir)
    File.symlink('public-keys.d', File.join(gpg_homedir, 'keys'))

    run = run_mitamae('homedir_target_symlink')
    expect_mitamae_failure(run, /is inside public-keys\.d, which gpg keeps in its homedir/)

    expect(File.exist?(File.join(gpg_homedir, 'public-keys.d'))).to be(false)
  end

  # The homedir is not there yet, so only its ancestors can be resolved -
  # and they have to be, or the comparison is of one side resolved against
  # the other as written.
  it 'refuses a collision the homedir reaches through a symlinked ancestor' do
    FileUtils.mkdir_p(temporary('real'))
    File.symlink('real', temporary('alias'))

    run = run_mitamae('homedir_alias_ancestor')
    expect_mitamae_failure(run, /is a file gpg keeps in its homedir/)

    expect(File.exist?(temporary('real/gnupg'))).to be(false)
  end

  # Every component reads one, so the suffix is refused rather than the
  # names: keyboxd.conf is as much a config file as gpg.conf.
  it 'refuses a keyring aimed at a component config file' do
    run = run_mitamae('homedir_target_conf')
    expect_mitamae_failure(run, /is a file gpg keeps in its homedir/)

    expect(File.exist?(gpg_homedir)).to be(false)
  end

  # `/` is its own separator, and a prefix built by concatenation would
  # read every path as outside it.
  it 'refuses a keyring aimed at a gpg file with the root as the homedir' do
    run = run_mitamae('homedir_root')
    expect_mitamae_failure(run, %r{/pubring\.kbx is a file gpg keeps in its homedir})

    expect(File.exist?('/pubring.kbx')).to be(false)
  end

  it 'places a keyring elsewhere inside the homedir, with a warning' do
    run = run_mitamae('homedir_target_inside')
    expect_mitamae_success(run)

    expect(run.log).to match(/WARN.*keyring path is inside the gpg homedir/)
    expect(fingerprint_of(File.join(gpg_homedir, 'inside.gpg'))).to eq(HOMEDIR_KEY_FINGERPRINT)
  end

  # The fetch runs in a throwaway homedir, so a key that fails the
  # assertions never reaches the one the recipe named.
  it 'puts nothing in the homedir when the fetched key is rejected' do
    run = run_mitamae('homedir_rejected_key')
    expect_mitamae_failure(run, /gpg user_id verification failed/)

    expect(File.exist?(temporary('homedir-rejected.gpg.asc'))).to be(false)
    expect(File.exist?(gpg_homedir)).to be(false)
  end

  # gpg initializes a homedir it is pointed at - a bare listing creates the
  # keyring and the trustdb - so an existing one with nothing in it yet is
  # never handed to gpg before the fetched key has been verified.
  it 'leaves an existing empty homedir untouched when the key is rejected' do
    FileUtils.mkdir_p(gpg_homedir)
    FileUtils.chmod(0o700, gpg_homedir)

    run = run_mitamae('homedir_rejected_key')
    expect_mitamae_failure(run, /gpg user_id verification failed/)

    expect(Dir.children(gpg_homedir)).to be_empty
  end

  # A homedir that does hold a keyring is read, and reading is where gpg
  # would build a trustdb it has no other reason to want here.
  it 'adds no trustdb to a homedir it only reads' do
    import_into_homedir(gpg_homedir, fixture('valid-key.asc'))
    FileUtils.rm_f(File.join(gpg_homedir, 'trustdb.gpg'))
    before = Dir.children(gpg_homedir).sort

    run = run_mitamae('homedir_rejected_key')
    expect_mitamae_failure(run, /gpg user_id verification failed/)

    expect(Dir.children(gpg_homedir).sort).to eq(before)
  end

  # gpg answers a homedir by creating the store its configuration names,
  # so a homedir holding one store and configured for the other must not
  # be handed to gpg at all.
  it 'builds no second key store in a homedir whose backend was switched' do
    skip 'GnuPG 1.4 has no keyboxd' if legacy_gpg?

    FileUtils.mkdir_p(gpg_homedir)
    FileUtils.chmod(0o700, gpg_homedir)
    File.write(File.join(gpg_homedir, 'common.conf'), "use-keyboxd\n")
    import_into_homedir(gpg_homedir, fixture('valid-key.asc'))
    kill_gpg_homedir(gpg_homedir)
    File.delete(File.join(gpg_homedir, 'common.conf'))
    before = homedir_entries(gpg_homedir)

    run = run_mitamae('homedir_rejected_key')
    expect_mitamae_failure(run, /gpg user_id verification failed/)

    expect(homedir_entries(gpg_homedir)).to eq(before)
  end

  # A keyboxd homedir answers a listing by starting its daemon, which adds
  # a socket and a lock file next to the database and then stays running.
  # No gpg option turns that off, so the listing that decides whether to
  # fetch is made over a copy of the store instead.
  it 'starts no keyboxd in a homedir it only reads' do
    skip 'GnuPG 1.4 has no keyboxd' if legacy_gpg?

    FileUtils.mkdir_p(gpg_homedir)
    FileUtils.chmod(0o700, gpg_homedir)
    File.write(File.join(gpg_homedir, 'common.conf'), "use-keyboxd\n")
    import_into_homedir(gpg_homedir, fixture('valid-key.asc'))
    kill_gpg_homedir(gpg_homedir)
    # Down to what a pre-provisioned homedir would hold: the daemon state
    # the suite's own import left behind is not what this is measuring.
    FileUtils.rm_f(Dir.glob(File.join(gpg_homedir, 'S.*')))
    FileUtils.rm_f(Dir.glob(File.join(gpg_homedir, 'public-keys.d', '{*.lock,.#*}')))
    before = homedir_entries(gpg_homedir)

    run = run_mitamae('homedir_rejected_key')
    expect_mitamae_failure(run, /gpg user_id verification failed/)

    expect(homedir_entries(gpg_homedir)).to eq(before)
  end

  # A homedir with `use-keyboxd` keeps its keys in public-keys.d instead of
  # a keyring file, and is still a homedir the key can come out of.
  it 'reuses the key in a keyboxd-backed homedir' do
    skip 'GnuPG 1.4 has no keyboxd' if legacy_gpg?

    FileUtils.mkdir_p(gpg_homedir)
    FileUtils.chmod(0o700, gpg_homedir)
    File.write(File.join(gpg_homedir, 'common.conf'), "use-keyboxd\n")
    import_into_homedir(gpg_homedir, fixture('valid-key.asc'))
    expect(File.exist?(File.join(gpg_homedir, 'public-keys.d', 'pubring.db'))).to be(true)

    run = run_mitamae('homedir_offline')
    expect_mitamae_success(run)

    expect(fingerprint_of(temporary('homedir-offline.gpg.asc'))).to eq(HOMEDIR_KEY_FINGERPRINT)
    expect(run.log).not_to include('--recv-keys')
  end
end

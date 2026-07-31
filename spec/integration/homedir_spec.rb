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

  # A trailing space is part of a directory's name, and `pwd` prints it
  # right before the newline the resolved path has to lose.
  it 'refuses the same collision when the homedir name ends in a space' do
    FileUtils.mkdir_p(temporary('gnupg '))
    FileUtils.chmod(0o700, temporary('gnupg '))

    run = run_mitamae('homedir_trailing_space')
    expect_mitamae_failure(run, /is a file gpg keeps in its homedir/)

    expect(Dir.children(temporary('gnupg '))).to be_empty
  end

  # Two names for one file, which no comparison of paths can see. The
  # homedir holds a key other than the one asked for, so a run that gets
  # past the guard has something to write and writes it through the link.
  it 'refuses a keyring hard-linked to one gpg keeps in the homedir' do
    import_into_homedir(gpg_homedir, fixture('colon-uid.asc'))
    # Whichever of the two the gpg under test wrote.
    keyring = %w[pubring.kbx pubring.gpg].detect { |name| File.exist?(File.join(gpg_homedir, name)) }
    before = File.binread(File.join(gpg_homedir, keyring))
    File.link(File.join(gpg_homedir, keyring), temporary('linked.gpg'))

    run = run_mitamae('homedir_target_hard_link')
    expect_mitamae_failure(run, /is a hard link to #{Regexp.escape(keyring)}, which gpg keeps in its homedir/)

    expect(File.binread(File.join(gpg_homedir, keyring))).to eq(before)
  end

  # One inode wears as many names as it is given, and the glob reaches
  # them in its own order: an unprotected one first must not answer for
  # the keyring behind it.
  it 'refuses a hard link the homedir also holds under a name of its own' do
    import_into_homedir(gpg_homedir, fixture('colon-uid.asc'))
    keyring = %w[pubring.kbx pubring.gpg].detect { |name| File.exist?(File.join(gpg_homedir, name)) }
    before = File.binread(File.join(gpg_homedir, keyring))
    # Sorts before either keyring name, so the glob finds it first.
    File.link(File.join(gpg_homedir, keyring), File.join(gpg_homedir, 'aaa'))
    File.link(File.join(gpg_homedir, keyring), temporary('linked.gpg'))

    run = run_mitamae('homedir_target_hard_link')
    expect_mitamae_failure(run, /is a hard link to #{Regexp.escape(keyring)}, which gpg keeps in its homedir/)

    expect(File.binread(File.join(gpg_homedir, keyring))).to eq(before)
  end

  it 'refuses a keyring aimed inside a directory gpg keeps in the homedir' do
    run = run_mitamae('homedir_target_keyboxd')
    expect_mitamae_failure(run, /is inside public-keys\.d, which gpg keeps in its homedir/)

    expect(File.exist?(gpg_homedir)).to be(false)
  end

  # Taking the dot segments out can uncover a name the resolver never
  # looked at, and here it is a symlink leading straight back to where the
  # target is.
  it 'refuses a collision uncovered by dropping a dot segment' do
    FileUtils.mkdir_p(temporary('h'))
    FileUtils.mkdir_p(temporary('real'))
    File.symlink('../real', temporary('h/alias'))

    run = run_mitamae('homedir_dot_segment_symlink')
    expect_mitamae_failure(run, /is a file gpg keeps in its homedir/)

    expect(File.exist?(temporary('h/new'))).to be(false)
    expect(Dir.children(temporary('real'))).to be_empty
  end

  # gpg locks a store by creating `<name>.lock` next to it, so that name is
  # as much gpg's as the store is.
  it 'refuses a keyring aimed at the lock of one of those files' do
    run = run_mitamae('homedir_target_lock')
    expect_mitamae_failure(run, /is a file gpg keeps in its homedir/)

    expect(File.exist?(gpg_homedir)).to be(false)
  end

  # A newline is a byte a name may end with and `$(...)` always takes off,
  # so the homedir - resolved by `pwd` alone - and the target - whose
  # parent goes through a capture - would disagree about which directory
  # they mean.
  it 'refuses the same collision when the homedir name ends in a newline' do
    FileUtils.mkdir_p(temporary("gnupg\n"))
    FileUtils.chmod(0o700, temporary("gnupg\n"))

    run = run_mitamae('homedir_trailing_newline')
    expect_mitamae_failure(run, /is a file gpg keeps in its homedir/)

    expect(Dir.children(temporary("gnupg\n"))).to be_empty
  end

  # Being one of those directories, rather than being under one: the write
  # would leave a plain file where gpg needs a directory.
  it 'refuses a keyring aimed at a directory gpg keeps in the homedir' do
    run = run_mitamae('homedir_target_keyboxd_dir')
    expect_mitamae_failure(run, /is public-keys\.d, which gpg keeps in its homedir/)

    expect(File.exist?(gpg_homedir)).to be(false)
  end

  # The same, for the directory the 2.1/2.2 releases keep the split TOFU
  # database in. The gpg running here writes the flat `tofu.db` and would
  # never create it, which is exactly why the name has to be reserved
  # rather than discovered: the homedir belongs to the caller, and theirs
  # may be read by a gpg that does.
  it 'refuses a keyring aimed at the split TOFU database directory' do
    run = run_mitamae('homedir_target_tofu_dir')
    expect_mitamae_failure(run, /is tofu\.d, which gpg keeps in its homedir/)

    expect(File.exist?(gpg_homedir)).to be(false)
  end

  # gpg renames a store to `<name>~` before rewriting it, so every name it
  # keeps has a second one - matched by the suffix rather than listed.
  it 'refuses a keyring aimed at the backup of one of those files' do
    run = run_mitamae('homedir_target_backup')
    expect_mitamae_failure(run, /is a file gpg keeps in its homedir/)

    expect(File.exist?(gpg_homedir)).to be(false)
  end

  # The reserved name is itself a symlink out of the homedir, so resolving
  # the target puts it somewhere else entirely - while gpg, given the same
  # name, walks that link too and creates its database at the other end.
  it 'refuses a keyring aimed at a reserved name that leads out of the homedir' do
    FileUtils.mkdir_p(gpg_homedir)
    FileUtils.chmod(0o700, gpg_homedir)
    FileUtils.mkdir_p(temporary('outside'))
    File.symlink(temporary('outside'), File.join(gpg_homedir, 'public-keys.d'))

    run = run_mitamae('homedir_target_keyboxd')
    expect_mitamae_failure(run, /is inside public-keys\.d, which gpg keeps in its homedir/)

    expect(Dir.children(temporary('outside'))).to be_empty
  end

  # Both at once: the target names the homedir through an alias, and the
  # reserved directory under it points back out again. Where the path
  # leads and how it is written each miss the name in the middle, which is
  # the one gpg uses.
  it 'refuses a keyring that reaches a reserved name through an alias of the homedir' do
    FileUtils.mkdir_p(gpg_homedir)
    FileUtils.chmod(0o700, gpg_homedir)
    FileUtils.mkdir_p(temporary('outside'))
    File.symlink(temporary('outside'), File.join(gpg_homedir, 'public-keys.d'))
    File.symlink(gpg_homedir, temporary('alias'))

    run = run_mitamae('homedir_alias_keyboxd')
    expect_mitamae_failure(run, /is inside public-keys\.d, which gpg keeps in its homedir/)

    expect(Dir.children(temporary('outside'))).to be_empty
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

  # A box that has moved to keyboxd sets `use-keyboxd` once, in GnuPG's own
  # configuration, and the homedirs on it then carry no common.conf at all
  # while every key still lives in public-keys.d.
  #
  # What this pins is the lookup that finds those keys. The export that
  # follows is gpg's own business and cannot be arranged from here: gpg
  # reads `use-keyboxd` from common.conf and nowhere else - on the command
  # line it answers "Please move option to common.conf" and goes on using
  # the keybox - and a common.conf in the homedir is the thing this case
  # is defined by not having. That half was checked by hand against a real
  # /etc/gnupg/common.conf, where the run places the key and fetches
  # nothing.
  it 'finds the key when keyboxd is enabled in GnuPG own configuration' do
    skip 'GnuPG 1.4 has no keyboxd' if legacy_gpg?

    FileUtils.mkdir_p(gpg_homedir)
    FileUtils.chmod(0o700, gpg_homedir)
    File.write(File.join(gpg_homedir, 'common.conf'), "use-keyboxd\n")
    import_into_homedir(gpg_homedir, fixture('valid-key.asc'))
    kill_gpg_homedir(gpg_homedir)
    # What such a homedir looks like: the store, and nothing local saying
    # which store it is.
    File.delete(File.join(gpg_homedir, 'common.conf'))
    expect(File.exist?(File.join(gpg_homedir, 'public-keys.d', 'pubring.db'))).to be(true)

    sysconfdir = temporary('etc-gnupg')
    FileUtils.mkdir_p(sysconfdir)
    File.write(File.join(sysconfdir, 'common.conf'), "use-keyboxd\n")

    run = with_gpgconf_sysconfdir(sysconfdir) { run_mitamae('homedir_offline') }
    expect_mitamae_success(run)

    # The recipe's keyserver is a port that refuses, so a fetch would end
    # the run: getting this far is itself the key having been found.
    expect(run.log).to include('gpg key already in homedir')
    expect(run.log).not_to include('--recv-keys')
  end

  # The other side of that: `use-keyboxd` in GnuPG's own configuration says
  # nothing about a gpg that has never heard of keyboxd, and a 1.4 with a
  # newer gpgconf beside it - which is exactly what a legacy run here is -
  # answers out of pubring.gpg whatever that file says.
  it 'ignores keyboxd configuration the gpg in use cannot read' do
    skip 'needs a gpg without keyboxd' unless legacy_gpg?

    import_into_homedir(gpg_homedir, fixture('valid-key.asc'))

    sysconfdir = temporary('etc-gnupg')
    FileUtils.mkdir_p(sysconfdir)
    File.write(File.join(sysconfdir, 'common.conf'), "use-keyboxd\n")

    run = with_gpgconf_sysconfdir(sysconfdir) { run_mitamae('homedir_offline') }
    expect_mitamae_success(run)

    expect(fingerprint_of(temporary('homedir-offline.gpg.asc'))).to eq(HOMEDIR_KEY_FINGERPRINT)
    expect(run.log).not_to include('--recv-keys')
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

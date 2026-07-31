module ::MItamae
  module Plugin
    module ResourceExecutor
      class GpgKeyring < ::MItamae::ResourceExecutor::File
        # import-minimal does not affect what gets exported (export-minimal
        # already decides that); it is here to bound the cost of importing a
        # poisoned key that carries tens of thousands of third-party
        # signatures, which makes a plain import effectively hang. Keys can
        # come from arbitrary URLs, so this is a deliberate defense, not
        # redundancy. self-sigs-only would be the precise tool but is
        # missing from older GnuPG; import-minimal (GnuPG >= 1.4.3) is the
        # portable equivalent.
        IMPORT_OPTIONS = ['--import-options', 'import-minimal'].freeze

        # --recv-keys takes its import options from --keyserver-options,
        # not from --import-options (see gpg(1) on keyserver-options:
        # "Valid import-options or export-options may be used here as well").
        KEYSERVER_IMPORT_OPTIONS = ['--keyserver-options', 'import-minimal'].freeze

        # Options for every key listing, shaped by what GnuPG versions
        # older than 2.1.15 need. Both are no-ops on newer ones, so the
        # listing is identical everywhere and only has to be parsed once.
        #
        # --fixed-list-mode keeps the primary uid in a uid record of its
        # own. Without it GnuPG 1.4 inlines that uid into the pub record
        # and emits no uid record for it at all, which reads here as a key
        # with no valid uid and breaks the user_id assertion. GnuPG 2.x is
        # always in fixed list mode; the option exists since 1.0.5.
        #
        # --fingerprint repeated adds the fpr records for sub keys. From
        # 2.1.15 on they are unconditional ("gpg: Always print fingerprint
        # records in --with-colons mode"); before that they are printed
        # only when the option is given twice, leaving the sub key check
        # with nothing to match.
        LIST_OPTIONS = ['--fixed-list-mode', '--fingerprint', '--fingerprint'].freeze

        # Oldest GnuPG this resource works with: import-minimal and
        # export-minimal, which every fetch depends on, arrived in 1.4.3.
        # Listings are already normalized across the whole range by
        # LIST_OPTIONS, so this is the only version that has to be named.
        MINIMUM_GPG_VERSION = '1.4.3'.freeze

        # Public key algorithms that need ECC support in gpg (RFC 6637
        # and RFC 8032 assignments). GnuPG carries none of them before
        # 2.1, which is what makes them worth naming: 1.4 rejects such a
        # key with "no valid user IDs", because it cannot check a
        # self-signature it has no algorithm for, and that message sends
        # everyone looking at the uids instead of the algorithm.
        ECC_PUBKEY_ALGORITHMS = {
          18 => 'ECDH',
          19 => 'ECDSA',
          22 => 'EdDSA',
        }.freeze

        # Algorithm names as `gpg --version` lists them. The names are
        # printed verbatim while the labels around them are translated,
        # so the whole output is searched rather than a "Pubkey:" line.
        ECC_ALGORITHM_NAMES = %w[ECDH ECDSA EDDSA].freeze

        # export-minimal drops third-party signatures, so the placed file
        # stays deterministic no matter what the source attached to the key
        # (keyservers since GnuPG 2.2.17 already strip them on receive,
        # older ones do not). Revocation signatures are self-signatures and
        # survive this.
        EXPORT_OPTIONS = ['--export-options', 'export-minimal'].freeze

        # The files gpg keeps directly in a homedir, across the versions
        # this resource supports: 1.4's keyrings next to 2.x's keybox, and
        # the state they write. 2.x's sockets are matched by their S.
        # prefix, and its configuration by the .conf suffix rather than by
        # name - gpg, gpg-agent, dirmngr, scdaemon, keyboxd and whatever
        # component comes next each read one, none of them is a place for
        # a keyring, and --no-options does not cover them anyway (they are
        # read by the libraries, not by gpg's option parser).
        #
        # Backups are matched by suffix for the same reason: gpg renames a
        # store to `<name>~` before rewriting it, so every name here has a
        # second one it never had to be listed under. Listing them is what
        # left `secring.gpg~` out while `pubring.gpg~` and `pubring.kbx~`
        # were in.
        GPG_HOMEDIR_FILES = %w[
          pubring.gpg pubring.kbx secring.gpg
          trustdb.gpg tofu.db random_seed .gpg-v21-migrated
          sshcontrol trustlist.txt
        ].freeze

        # The directories gpg keeps under a homedir. Nothing inside them is
        # a place for a keyring either - public-keys.d holds the keyboxd
        # database, and the rest hold key material, revocations and CRLs.
        #
        # tofu.d is the split form of the tofu.db above: the 2.1 and 2.2
        # releases write the TOFU state as a directory when
        # --tofu-db-format is split, and later ones dropped the format
        # without freeing the name. Both spellings are reserved because
        # the homedir is the caller's - the gpg placing the keyring is not
        # necessarily the only one that will read it.
        GPG_HOMEDIR_DIRS = %w[
          public-keys.d private-keys-v1.d openpgp-revocs.d crls.d tofu.d
        ].freeze

        # What says a homedir has keys to look at, one list per store:
        # 2.x's keybox alongside 1.4's keyring, and the keyboxd database
        # that replaces both in a homedir whose common.conf turns keyboxd
        # on.
        GPG_KEYRING_FILES = %w[pubring.kbx pubring.gpg].freeze
        GPG_KEYBOXD_FILES = %w[public-keys.d/pubring.db].freeze

        # Public keyservers fail intermittently, so network fetches are
        # retried with exponential backoff before the run gives up.
        RETRY_LIMIT = 3
        RETRY_INTERVAL = 2 # seconds, doubled after every failed attempt

        private

        @tempfile = nil

        # Runs the block until its command result succeeds, backing off
        # exponentially between attempts. Always returns the last result;
        # raising on final failure stays at the call site.
        def with_retry(subject)
          interval = RETRY_INTERVAL
          attempt = 1
          while true
            result = yield
            return result if result.exit_status == 0
            return result if attempt >= RETRY_LIMIT
            MItamae.logger.warn "#{subject} failed (attempt #{attempt}/#{RETRY_LIMIT}), retrying in #{interval} seconds..."
            sleep interval
            attempt += 1
            interval *= 2
          end
        end

        # Compares dotted version strings numerically, so that 1.4.23 is
        # newer than 1.4.3 (a plain string compare gets that wrong).
        def version_at_least?(actual, minimum)
          actual_parts = actual.split('.').map {|part| part.to_i }
          minimum_parts = minimum.split('.').map {|part| part.to_i }
          minimum_parts.length.times do |i|
            current = actual_parts[i] ? actual_parts[i] : 0
            required = minimum_parts[i]
            return true if current > required
            return false if current < required
          end
          true
        end

        # The version of the gpg in use, or nil where its banner says
        # nothing recognizable. Anchored to GnuPG's own banner ("gpg
        # (GnuPG) 2.4.4", or "gpg (GnuPG/MacGPG2) 2.2.41" once repackaged)
        # rather than to the first number on the first line: a wrapper
        # that announces itself first would otherwise have its own version
        # read as gpg's.
        def gpg_version
          if @gpg_version.nil?
            result = run_command(['gpg', '--version'], error: false)
            match = result.exit_status == 0 ? /\(GnuPG[^)]*\)\s+(\d+\.\d+(\.\d+)?)/.match(result.stdout) : nil
            @gpg_version = match ? match[1] : false
          end
          @gpg_version ? @gpg_version : nil
        end

        # Checked up front so an ancient gpg is named as such, instead of
        # failing later as an unknown-option error from inside a fetch.
        def verify_gpg_version
          version = gpg_version

          if version.nil?
            # A build that prints no recognizable banner is left alone.
            # Refusing to run on a version that cannot be read would be
            # worse than letting the actual gpg invocations speak for
            # themselves.
            MItamae.logger.debug 'could not read the gpg version, skipping the minimum version check'
            return
          end

          MItamae.logger.debug "gpg version: #{version}"
          return if version_at_least?(version, MINIMUM_GPG_VERSION)

          raise "`gpg` is #{version}, but mitamae's gpg_keyring needs GnuPG #{MINIMUM_GPG_VERSION} or newer (--import-options import-minimal)."
        end

        # Whether the gpg in use carries ECC at all. Read from its own
        # algorithm list, so a build without ECC support is recognized
        # even on a version new enough to have it.
        def gpg_supports_ecc?
          if @gpg_supports_ecc.nil?
            result = run_command(['gpg', '--version'], error: false)
            # Unreadable output must not turn into a claim about the
            # binary, so assume support and stay quiet.
            @gpg_supports_ecc = result.exit_status != 0 ||
                                ECC_ALGORITHM_NAMES.any? {|name| result.stdout.include?(name) }
          end
          @gpg_supports_ecc
        end

        # Reads the primary key's algorithm out of gpg's packet dump.
        # Parsing output is usually a trap, but these dump lines are
        # written with a plain fprintf in gpg (no translation), so the
        # number can be read whatever the locale is. Returns nil unless
        # the key turns out to be one this gpg cannot handle.
        def unsupported_algorithm(path)
          return nil if gpg_supports_ecc?

          result = run_command(['gpg', '--list-packets', path], error: false)
          return nil if result.exit_status != 0

          line = result.stdout.lines.detect {|l| l.include?(':public key packet:') }
          # The algorithm sits on the line after the packet header.
          index = line ? result.stdout.lines.index(line) : nil
          match = index ? /algo (\d+)/.match(result.stdout.lines[index + 1].to_s) : nil
          return nil if match.nil?

          name = ECC_PUBKEY_ALGORITHMS[match[1].to_i]
          name ? "public key algorithm #{match[1]} (#{name})" : nil
        end

        # The receive path never gets a file of its own to inspect - the
        # key fails inside gpg - so the gap can only be pointed at, not
        # proven. Worth saying anyway: on a binary without ECC support it
        # is the likeliest reason a receive fails.
        def missing_ecc_note
          return '' if gpg_supports_ecc?

          ' (note: the gpg in use has no ECC support, so an ECC key cannot be received by it)'
        end

        # mitamae rescues Backend::CommandExecutionError and logs only
        # "<resource> Failed.", dropping the message with it, so a
        # failure that has something to explain is raised as a plain
        # error - which mitamae does print - while the ones with nothing
        # to add keep the original type.
        def raise_command_failure(subject, note)
          raise "#{subject}#{note}" unless note.empty?

          raise MItamae::Backend::CommandExecutionError, subject
        end

        # Appended to an import failure so the cause is named instead of
        # left to gpg's misleading uid complaint.
        def unsupported_algorithm_note(path)
          algorithm = unsupported_algorithm(path)
          return '' if algorithm.nil?

          ": the key uses #{algorithm}, which the gpg in use does not support (GnuPG 2.1 or newer is required for ECC keys)"
        end

        def gpg(homedir, args)
          [
            'gpg',
            '--homedir', homedir,
            # A homedir given by the recipe belongs to the caller and may
            # carry a gpg.conf whose options (armor, export-options, ...)
            # would silently change what this resource writes. Everything
            # this resource depends on is passed explicitly, so the config
            # file is ignored outright and runs stay deterministic.
            '--no-options',
            # Nothing here consults the web of trust - the fingerprint
            # picks the key - and without this gpg builds a trustdb the
            # moment it reads a keyring, which in a homedir the recipe
            # named is a database the caller never asked this resource to
            # add. Accepted by every version in range (1.4.2 and up).
            '--trust-model', 'always',
            '--quiet',
            '--batch',
            '--with-colons',
          ].concat(args)
        end

        # gpg only auto-creates the default ~/.gnupg; an explicit --homedir
        # that does not exist just fails ("no writable keyring found"). The
        # mode applies to directories this creates - an existing homedir
        # keeps whatever permissions its owner chose.
        #
        # `--` because the path is the recipe's: a relative one starting
        # with `-` is a directory like any other, and without the
        # terminator mkdir reads it as more options and the run ends on
        # `invalid option`. Every other command handed a path from the
        # recipe takes the same treatment.
        def prepare_homedir(homedir)
          result = run_command(['mkdir', '-p', '-m', '0700', '--', homedir], error: false)
          if result.exit_status != 0
            raise MItamae::Backend::CommandExecutionError, "gpg homedir: #{homedir}"
          end
        end

        # The keyring file is placed after the homedir has been updated, so
        # a target inside the homedir lands on whatever gpg keeps under
        # that name - and the run still exits 0, with the damage showing up
        # only the next time that homedir is used. The check is on the name
        # rather than on what is there: gpg creates most of these on
        # demand, so "not there yet" is no reason to allow the collision.
        # Every layout in range is covered at once - 1.4's pubring.gpg,
        # 2.x's pubring.kbx, keyboxd's public-keys.d - as are 2.x's
        # sockets, by their S. prefix.
        def verify_target_outside_homedir(homedir)
          relative = homedir_relative_path(homedir)

          # Every way of placing the target, because the write lands on
          # gpg's file by any of them. Resolved says where the bytes end
          # up; the paths as written say which name gpg is given, and gpg
          # walks the same links the write does - a `public-keys.d` that
          # is a symlink out of the homedir puts the resolved target
          # somewhere else entirely while staying the path keyboxd creates
          # its database at, which is then the file the keyring lands on;
          # and the walk finds the homedir under whatever other name the
          # target reached it by, which neither of the other two can see.
          [relative,
           lexical_homedir_relative_path(homedir),
           alias_homedir_relative_path(homedir)].each do |name|
            next if name.nil?
            next unless protected_homedir_entry?(name)

            entry = name.split('/')[0]
            if name.include?('/')
              raise "#{attributes.path} is inside #{entry}, which gpg keeps in its homedir, and the keyring is written after the homedir is updated; place the keyring outside #{homedir}"
            end
            # The target *is* one of gpg's directories, rather than
            # something under one. A run that writes it leaves a plain
            # file where a directory belongs, which gpg only finds out
            # about when it next needs the directory ("Not a directory").
            if GPG_HOMEDIR_DIRS.include?(entry)
              raise "#{attributes.path} is #{entry}, which gpg keeps in its homedir, and the keyring is written after the homedir is updated; place the keyring outside #{homedir}"
            end
            raise "#{attributes.path} is a file gpg keeps in its homedir, and the keyring is written after the homedir is updated; place the keyring outside #{homedir}"
          end

          # A hard link is a second name for one file, and no amount of
          # resolving turns two names into one: the write opens the target
          # and truncates what is behind it, so a target linked to one of
          # gpg's own files destroys that file while every comparison
          # above - which only ever sees paths - reads it as somewhere
          # else entirely. It is asked after those, not instead of them,
          # because only a target that already exists can be a link, and
          # theirs is the case where nothing is there yet.
          linked = linked_homedir_entries(homedir).detect {|entry| protected_homedir_entry?(entry) }
          unless linked.nil?
            raise "#{attributes.path} is a hard link to #{linked}, which gpg keeps in its homedir, and the keyring is written after the homedir is updated; place the keyring outside #{homedir}"
          end

          return if relative.nil?

          # Any other name in there is the recipe's business - it works,
          # and the resource has no say in how someone lays out their
          # directories. Still worth a word: nothing but this warning
          # stands between that layout and a name gpg decides to use.
          MItamae.logger.warn "keyring path is inside the gpg homedir: #{attributes.path} (it is written after the homedir is updated, so a name gpg uses would be overwritten)"
        end

        # Whether a path relative to the homedir names something gpg keeps
        # there. The first segment is what decides, and one of gpg's
        # directories is refused whether the target is under it or is it -
        # a keyring written over the name leaves a file where gpg needs a
        # directory. Anything deeper than one segment is that case and
        # nothing else; the file names only answer for a segment on its
        # own. Kept in one place because both the path and the hard link
        # reach the same question by different routes, and a name gpg
        # starts using has to be learned once rather than twice.
        def protected_homedir_entry?(relative)
          entry = relative.split('/')[0]
          if GPG_HOMEDIR_DIRS.include?(entry)
            true
          elsif relative.include?('/')
            false
          else
            # Every name gpg keeps brings two more with it: `<name>~`, the
            # backup it renames a store to before rewriting it, and
            # `<name>.lock`, the lock it takes over it - a keyring written
            # over that one is read as a lock held by a process that does
            # not exist ("invalid pid -1 in lockfile"), and gpg then
            # refuses the keyring it names. Both come off the end rather
            # than being listed, so the list stays one entry per file.
            # `.#lk...` is the other half of that locking, named after the
            # inode and unpredictable, so it goes by its prefix like the
            # sockets do.
            name = entry
            name = name[0..-6] if name.end_with?('.lock')
            name = name[0..-2] if name.end_with?('~')
            GPG_HOMEDIR_FILES.include?(name) or entry.start_with?('S.') or
              entry.start_with?('.#lk') or entry.end_with?('.conf')
          end
        end

        # The names, relative to the homedir, of the files the target is
        # another name for. `-ef` compares device and inode, which is the
        # only thing that answers this; the walk is over the homedir
        # rather than over the target, since a link is found from either
        # end and only one of the two is a directory that can be listed.
        # One level down is as deep as it goes, which is as deep as gpg's
        # own layout is.
        #
        # Every one of them, not the first: one inode can wear as many
        # names as someone cares to give it, and `pubring.kbx` with an
        # `aaa` beside it would otherwise be answered for by whichever the
        # glob reached first. A NUL separates them, being the one byte a
        # name cannot contain.
        LINKED_HOMEDIR_ENTRIES = [
          '[ -f "$1" ] || exit 1',
          'cd -- "$2" 2>/dev/null || exit 1',
          'for c in * .* */*; do',
          '  [ -f "$c" ] || continue',
          '  [ "$1" -ef "$c" ] || continue',
          '  printf "%s\\0" "$c"',
          'done',
        ].join("\n").freeze

        def linked_homedir_entries(homedir)
          # Resolved, because the walk runs from inside the homedir and a
          # path the recipe wrote relative to mitamae's working directory
          # would name nothing from there.
          result = run_command(['sh', '-c', LINKED_HOMEDIR_ENTRIES, 'sh', resolve_path(attributes.path), homedir], error: false)
          return [] if result.exit_status != 0

          result.stdout.split("\0").reject {|entry| entry.empty? }
        end

        # Where the target sits under the homedir, or nil if it is outside
        # it. Both sides are resolved first, because the classification
        # above reads a path as written while the write follows what the
        # path actually leads to: `./gnupg` and `gnupg` are the same
        # directory, so are two names joined by a symlink, and a symlink
        # anywhere in between - `gnupg/keys` pointing at
        # `gnupg/public-keys.d` - hides a protected directory behind an
        # unprotected name. Both go through the same resolver, or the
        # comparison could be of one path resolved against another as
        # written, which agrees on nothing.
        def homedir_relative_path(homedir)
          relative_to(resolve_path(homedir), resolve_path(attributes.path))
        end

        # The same question put to the paths as written - expanded and
        # normalized, never resolved - which is the only thing that still
        # sees a reserved name whose own link leads out of the homedir.
        def lexical_homedir_relative_path(homedir)
          relative_to(normalize_path(File.expand_path(homedir)),
                      normalize_path(File.expand_path(attributes.path)))
        end

        # And the same question again for a target that reaches the
        # homedir under another name. Neither comparison above sees that
        # one: resolving takes both sides all the way through their links,
        # so a reserved directory pointing out of the homedir carries the
        # target out with it, while the paths as written cannot tell that
        # `/alias` is the homedir at all. The walk can. It steps down the
        # target's own components until one of them *is* the homedir -
        # compared by device and inode, so every alias of it counts - and
        # what is left is the part gpg is going to name too.
        #
        # A homedir that is not there yet has no aliases and ends the walk
        # at once. Nothing inside it exists either, so the comparisons
        # above have nothing to be fooled by and answer it between them.
        ALIAS_HOMEDIR_RELATIVE = [
          '[ -e "$2" ] || exit 1',
          'p=/',
          'rest=${1#/}',
          'while :; do',
          '  if [ "$p" -ef "$2" ]; then',
          '    printf "%s\\0" "$rest"',
          '    exit 0',
          '  fi',
          '  [ -n "$rest" ] || exit 1',
          '  seg=${rest%%/*}',
          '  case $rest in *"/"*) rest=${rest#*/} ;; *) rest= ;; esac',
          '  case $p in /) p=/$seg ;; *) p=$p/$seg ;; esac',
          '  [ -e "$p" ] || exit 1',
          'done',
        ].join("\n").freeze

        def alias_homedir_relative_path(homedir)
          target = normalize_path(File.expand_path(attributes.path))
          result = run_command(['sh', '-c', ALIAS_HOMEDIR_RELATIVE, 'sh', target, homedir], error: false)
          return nil if result.exit_status != 0

          rest = result.stdout.split("\0")[0]
          rest.nil? || rest.empty? ? nil : rest
        end

        def relative_to(root, target)
          # `/` is its own separator, so the prefix is built rather than
          # concatenated: `//` matches nothing, and a homedir of `/` would
          # have every target read as outside it.
          prefix = root.eql?('/') ? '/' : root + '/'
          return nil unless target.start_with?(prefix)

          target[prefix.length..-1]
        end

        # The shell does the resolving, since it walks every component of a
        # path for free and needs no realpath(1) - not every box has one,
        # and the ones that do disagree about the flags.
        #
        # `dir_of` answers for a path's directory, and answers for one that
        # is not there yet: it descends to the deepest directory that does
        # exist, resolves that, and puts the rest back. A directory this
        # run is about to create - keyboxd's public-keys.d, say - is then
        # still named as what it will be, rather than losing the path to a
        # failed `cd`. A component that is a symlink to something not there
        # yet is followed on the way down, since it will lead there as soon
        # as the import creates it.
        #
        # Around it, the last component is followed for as long as it keeps
        # being a symlink, because writing the keyring writes through the
        # whole chain, and the directory is resolved again after every hop
        # so a link that leads out of the homedir is read as leading out of
        # it. The hop count is what a chain cannot outlast: Linux gives up
        # at 40 itself, and stopping there means a loop ends the walk
        # instead of spinning it. Still a symlink by then is a path that
        # cannot be resolved, and is reported as such rather than answered
        # with the last name the walk happened to be on.
        #
        # A path that is already a directory takes none of that: `cd` into
        # it and it says where it is. This is also what keeps `/` out of
        # the walk, whose basename is `/` again.
        #
        # `$(...)` takes every trailing newline off what it captures, and a
        # newline is as much part of a name as any other byte: a directory
        # called "gnupg\n" comes back from `pwd` as "gnupg", which is a
        # different directory - and one the target then reads as being
        # inside. Every capture below therefore ends in a sentinel `x`,
        # taken off again together with the single newline the command
        # itself wrote; dirname, basename, readlink and pwd each write
        # exactly one. The answer carries the same sentinel out, since the
        # caller cannot otherwise tell the newline `pwd` adds from one the
        # name ends with.
        RESOLVE_PATH = [
          "nl='",
          "'",
          'if [ -d "$1" ]; then',
          '  cd -- "$1" 2>/dev/null || exit 1',
          '  pwd -P',
          '  printf x',
          '  exit 0',
          'fi',
          'dir_of() {',
          '  p=$(dirname -- "$1"; printf x); p=${p%x}; p=${p%"$nl"}',
          '  t=',
          '  m=0',
          '  while [ ! -d "$p" ]; do',
          '    case $p in /|.) break ;; esac',
          '    if [ -L "$p" ]; then',
          '      m=$((m + 1))',
          '      [ "$m" -gt 40 ] && return 1',
          '      k=$(readlink -- "$p"; printf x); k=${k%x}; k=${k%"$nl"}',
          '      case $k in',
          '        /*) ;;',
          '        *) q=$(dirname -- "$p"; printf x); q=${q%x}; q=${q%"$nl"}; k=$q/$k ;;',
          '      esac',
          '      p=$k',
          '      continue',
          '    fi',
          '    s=$(basename -- "$p"; printf x); s=${s%x}; s=${s%"$nl"}',
          '    t=$s${t:+/$t}',
          '    p=$(dirname -- "$p"; printf x); p=${p%x}; p=${p%"$nl"}',
          '  done',
          '  r=$(cd -- "$p" 2>/dev/null && pwd -P && printf x) || return 1',
          '  r=${r%x}; r=${r%"$nl"}',
          '  case $r in /) r= ;; esac',
          '  printf "%sx" "$r${t:+/$t}"',
          '}',
          'd=$(dir_of "$1") || exit 1; d=${d%x}',
          'b=$(basename -- "$1"; printf x); b=${b%x}; b=${b%"$nl"}',
          'n=0',
          'while [ -L "$d/$b" ]; do',
          '  n=$((n + 1))',
          '  [ "$n" -gt 40 ] && exit 1',
          '  l=$(readlink -- "$d/$b"; printf x); l=${l%x}; l=${l%"$nl"}',
          '  case $l in /*) ;; *) l=$d/$l ;; esac',
          '  d=$(dir_of "$l") || exit 1; d=${d%x}',
          '  b=$(basename -- "$l"; printf x); b=${b%x}; b=${b%"$nl"}',
          'done',
          'printf "%s/%s\nx" "$d" "$b"',
        ].join("\n").freeze

        # A path that cannot be resolved at all - a symlink loop - is left
        # as written and only expanded. Nothing can be written through it
        # either, so it is not a way past the checks above.
        #
        # Either answer is then normalized, because the resolver returns
        # the components that do not exist yet exactly as they were
        # written: `/var/lib/new/..` with no `new` on disk resolves to
        # itself, and a target of `/var/lib/pubring.kbx` reads as outside
        # a homedir that `mkdir -p` is about to make mean `/var/lib`.
        # Only the resolver's own line terminator comes off, because
        # everything else it prints is the path: a directory may
        # legitimately be named with a trailing space, and stripping it
        # turns a homedir of `/srv/gnupg ` into `/srv/gnupg` while the
        # target inside it keeps the space - two strings that no longer
        # contain one another. Which terminator is the resolver's is what
        # the sentinel byte after it answers, a name being free to end in
        # a newline too. Anything else coming back is not an answer at
        # all, and is read as a resolver failure.
        #
        # Normalizing can hand back a path the resolver has not looked at:
        # dropping `new/..` from `h/new/../alias` uncovers `h/alias`,
        # which may be a symlink of its own - and is what the kernel walks
        # once `mkdir -p` creates `new`. So the answer goes back in until
        # it stops changing, which for a path with no dot segments in it
        # is the first time round. The count is a backstop rather than a
        # budget: nothing known reaches it, and a path that would is
        # answered like one that cannot be resolved at all.
        def resolve_path(path)
          candidate = path
          41.times do
            result = run_command(['sh', '-c', RESOLVE_PATH, 'sh', candidate], error: false)
            break unless result.exit_status == 0 and result.stdout.end_with?("\nx")

            answer = result.stdout[0..-3]
            normalized = normalize_path(answer)
            return normalized if normalized.eql?(answer)

            candidate = normalized
          end
          normalize_path(File.expand_path(path))
        end

        # Drops `.` and `..` from an already resolved path, which is the
        # one place it can be done by string alone. Everything in front of
        # a leftover `..` has been through `cd -P`, or is a directory this
        # run is about to create - and `mkdir -p` creates directories,
        # never symlinks - so no component it walks back out of can be a
        # link that would send the kernel somewhere else. `..` at the root
        # is the root, as it is on disk.
        #
        # Empty segments go with them, which covers the leading `//` that
        # survives the resolving: POSIX leaves it to the implementation,
        # and Linux answers `cd //tmp && pwd -P` with `//tmp` while
        # meaning the same directory as `/tmp`. Two paths for one
        # directory is the thing this whole comparison is trying not to be
        # fooled by.
        def normalize_path(path)
          segments = []
          path.split('/').each do |segment|
            case segment
            when '', '.'
              next
            when '..'
              segments.pop
            else
              segments << segment
            end
          end
          '/' + segments.join('/')
        end

        def list_keys(homedir)
          result = run_command(gpg(homedir, LIST_OPTIONS), error: false)
          if result.exit_status != 0
            raise MItamae::Backend::CommandExecutionError, "gpg list keys: #{homedir}"
          end

          parse_colons(result.stdout.lines)
        end

        # The same listing, asked about a homedir that is the caller's
        # rather than this resource's, which changes both what a failure
        # means and where the question may be put. The only thing being
        # asked is whether the fetch can be skipped, so a homedir with
        # nothing to offer - not there yet, no store in it yet, or refused
        # by gpg for reasons of its own - is read as holding nothing and
        # the fetch goes ahead.
        #
        # The caller's directory is never the one handed to gpg. gpg does
        # not just read a homedir it is pointed at, and no option makes it:
        # a listing creates the store its configuration names, builds a
        # trustdb (--trust-model always covers that one), and on a keyboxd
        # homedir starts the daemon, which adds its socket and a lock file
        # and then stays running. This lookup happens before the fetched
        # key has been verified, so all of that would be state left in a
        # caller's directory by a run that went on to reject the key. What
        # is listed instead is a throwaway homedir holding a copy of the
        # store - the same files homedir_store_files names, so nothing new
        # has to be kept current - and whatever gpg initializes it with is
        # thrown away with it.
        #
        # A missing directory is answered without any of that, and saying
        # so beats offering it to gpg, which only draws a "Fatal:" line
        # that reads like a real problem in the log.
        def homedir_keys(homedir)
          if run_command(['test', '-d', homedir], error: false).exit_status != 0
            # Said out loud rather than logged at debug: a homedir that is
            # not there is as likely to be a typo in the recipe as a first
            # run, and the two look identical from here - both fetch, and
            # both end with a directory of that name holding the key.
            MItamae.logger.warn "gpg homedir does not exist: #{homedir} (created with mode 0700 once a fetched key has been verified)"
            return []
          end

          keyboxd = keyboxd_homedir?(homedir)
          names = homedir_store_files(homedir, keyboxd)
          return [] if names.empty?

          records = []
          Dir.mktmpdir{|workdir|
            copy = File.join(workdir, 'gnupg')
            prepare_homedir(copy)

            # Written rather than copied from the caller's: the only thing
            # the copy needs from common.conf is which store to read, and
            # the rest of that file is the caller's configuration, which
            # --no-options exists to keep out of this resource's runs.
            if keyboxd
              File.open(File.join(copy, 'common.conf'), 'w') do |f|
                f.write("use-keyboxd\n")
              end
            end

            if copy_store_files(homedir, copy, names)
              result = run_command(gpg(copy, LIST_OPTIONS), error: false)
              records = parse_colons(result.stdout.lines) if result.exit_status == 0
            end

            kill_keyboxd(copy) if keyboxd
          }
          records
        end

        # The store files the homedir actually has, asked of the store its
        # configuration selects rather than of whatever store file happens
        # to be in it. The two can disagree - a migration onto keyboxd left
        # half done, or `use-keyboxd` taken back out again - and a homedir
        # configured for a store it does not have holds no keys this can
        # reuse, whatever else is lying in it.
        def homedir_store_files(homedir, keyboxd)
          names = keyboxd ? GPG_KEYBOXD_FILES : GPG_KEYRING_FILES
          names.select {|name|
            run_command(['test', '-e', File.join(homedir, name)], error: false).exit_status == 0
          }
        end

        # Copies the store into the throwaway homedir. A failure is not
        # raised on: an unreadable store is one more homedir with nothing
        # to offer, and the fetch that follows is the answer to that.
        def copy_store_files(homedir, copy, names)
          names.all? {|name|
            parent = File.dirname(File.join(copy, name))
            if parent != copy
              result = run_command(['mkdir', '-p', '-m', '0700', '--', parent], error: false)
              next false if result.exit_status != 0
            end

            run_command(['cp', '--', File.join(homedir, name), File.join(copy, name)], error: false).exit_status == 0
          }
        end

        # The daemon a keyboxd listing starts outlives the directory it was
        # started for, so it is asked to stop before that directory goes.
        # `gpgconf --kill` is not the way to ask: GnuPG 2.4 exits 0 for
        # keyboxd and leaves it running. Nothing here is fatal - a stray
        # daemon holding a deleted temporary directory is untidy, not
        # wrong - so every step may fail quietly.
        def kill_keyboxd(homedir)
          result = run_command(['gpgconf', '--homedir', homedir, '--list-dirs', 'socketdir'], error: false)
          return if result.exit_status != 0

          socket = File.join(result.stdout.strip, 'S.keyboxd')
          run_command(['gpg-connect-agent', '-S', socket, 'KILLKEYBOXD', '/bye'], error: false)
        end

        # Which store a homedir's keys are in is settled by `use-keyboxd`,
        # and by two files that can set it: common.conf in the homedir and
        # a system-wide one next to the rest of GnuPG's configuration. A
        # box that has moved to keyboxd sets it once, in the system file,
        # and the homedirs on it then carry no common.conf at all while
        # every key still lives in public-keys.d. Both are read by GnuPG's
        # libraries rather than by gpg's option parser, so --no-options
        # does not turn any of it off.
        #
        # Rather than find those files and read them, the question goes to
        # the binary that will answer out of them. `--gpgconf-list` prints
        # the options gpgconf shows for the gpg that is running - it is
        # how gpgconf itself asks - with `use_keyboxd` among them and its
        # value already resolved from both files.
        #
        # That is the only spelling of this question that cannot end up
        # describing a different installation. `gpgconf --list-dirs`
        # answers for the gpgconf found on PATH, which in a split
        # installation is not the GnuPG placing this keyring, and a
        # version check on gpg only says the binary could read such a file
        # - never that the file that was found is one it reads. Asking gpg
        # binds the answer to the binary by construction.
        #
        # A gpg with no keyboxd prints no use_keyboxd line at all: 1.4
        # prints a handful of unrelated options, and the versions before
        # 2.3 stop short of this one. The missing line is the answer for
        # those rather than a failure to get one, which is what the
        # version check was there for. The command creates nothing in the
        # homedir - not even the homedir - which is what makes it usable
        # on a directory belonging to the caller.
        def keyboxd_homedir?(homedir)
          result = run_command(gpg(homedir, ['--gpgconf-list']), error: false)
          return false if result.exit_status != 0

          result.stdout.lines.any? {|line|
            # `name:flags:value:`, and the value of a boolean option is the
            # number of times it is set - anything but 0 is on.
            fields = line.strip.split(':')
            fields[0].eql?('use_keyboxd') and !fields[2].to_s.empty? and !fields[2].eql?('0')
          }
        end

        # gpg escapes ':' and '\' (and control characters) in colon-format
        # field values as C-style \xNN sequences (see gnupg doc/DETAILS).
        # Without decoding, a uid like "Colon: User" is stored as
        # "Colon\x3a User" and can never exact-match the natural string
        # given in the user_id attribute.
        def unescape_colons(value)
          value.gsub(/\\x[0-9a-fA-F]{2}/) { |match| match[2, 2].to_i(16).chr }
        end

        # Parses `gpg --with-colons` key listing lines into one record per
        # pub key: { fingerprint:, uids:, sub_fingerprints: }. uid and sub
        # entries belong to the pub record they follow.
        def parse_colons(lines)
          records = []
          record = nil
          section = nil
          lines.each do |line|
            entry = line.strip.split(':')
            case entry[0]
            when 'pub'
              record = { fingerprint: nil, uids: [], sub_fingerprints: [] }
              records << record
              section = 'pub'
            when 'sub'
              section = 'sub'
            when 'fpr'
              case section
              when 'pub'
                record[:fingerprint] = entry[9]
              when 'sub'
                record[:sub_fingerprints] << entry[9]
              else
                raise 'unknown type'
              end
              section = nil
            when 'uid'
              # A whitelist of "valid" states would break on placed files:
              # without a trustdb every live uid lists as '-' (unknown), so
              # only the states that mark a uid as dead are excluded.
              record[:uids] << unescape_colons(entry[9]) if record && !%w[r e].include?(entry[1])
            end
          end
          records
        end

        # A fingerprint that matches a sub key is a recipe mistake worth its
        # own message: treated as a plain mismatch it would trigger an
        # endless re-fetch loop (the fetch finds the key, the export writes
        # the primary fingerprint, the next run mismatches again).
        def raise_if_sub_key_fingerprint(records, source)
          sub_owner = records.detect {|r| r[:sub_fingerprints].include?(desired.fingerprint) }
          if sub_owner
            raise "fingerprint #{desired.fingerprint} is a sub key of #{sub_owner[:fingerprint]}; specify the primary key fingerprint (#{source})"
          end
        end

        # user_id is an assertion, not a convergible attribute: a keyring
        # cannot be "fixed" into carrying the requested uid, so a mismatch
        # stops the run instead of updating the file. The match is an exact
        # string comparison against the key's valid uids.
        def verify_user_id(uids, source)
          return unless desired.user_id

          if uids.empty?
            # Only raise when user_id was requested: keys.openpgp.org
            # serves unverified keys without any user id, so an empty uid
            # set is a normal state for fingerprint-only recipes.
            raise "gpg user_id verification failed: key from #{source} has no valid user id; remove the user_id attribute if this is expected (keys.openpgp.org serves unverified keys without user ids)"
          end

          unless uids.include?(desired.user_id)
            raise "gpg user_id verification failed: expected #{desired.user_id.inspect}, key from #{source} has #{uids.inspect}"
          end
        end

        def run_action(action)
          if run_command(['which', 'gpg'], error: false).exit_status != 0
            raise "`gpg` command is not available. Please install gnupg to use mitamae's gpg_keyring."
          end

          if run_command(['which', 'curl'], error: false).exit_status != 0
            raise "`curl` command is not available. Please install curl to use mitamae's gpg_keyring."
          end

          verify_gpg_version

          super
        end

        def set_desired_attributes(desired, action)
          super

          desired.fingerprint = desired.fingerprint.strip.upcase.delete(' ').delete_prefix('0X')
          if desired.fingerprint.length != 40
            raise 'unknown fingerprint'
          end
          MItamae.logger.debug "fingerprint: #{desired.fingerprint}"

          if !desired.keyserver
            desired.keyserver = 'hkps://keys.openpgp.org'
          end
          MItamae.logger.debug "keyserver: #{desired.keyserver}"

          if desired.homedir
            MItamae.logger.debug "homedir: #{desired.homedir}"
            # Decided from the recipe alone, so it is settled here rather
            # than on the path that writes: a keyring aimed at one of
            # gpg's own files is wrong for the delete action too.
            verify_target_outside_homedir(desired.homedir)
          end
        end

        def set_current_attributes(current, action)
          super

          # Deletion only cares whether the file exists: reading and
          # asserting the key here would just block removing an obsolete
          # keyring (e.g. one whose asserted uid has since been revoked).
          return if action == :delete

          return unless current.exist

          records = []

          # Reading the placed file always uses a throwaway homedir, even
          # when the recipe names one: importing into the recipe's homedir
          # would both mutate it and mix its other keys into this listing,
          # which the multi-key guard below reads as the file's contents.
          Dir.mktmpdir{|homedir|
            result = run_command(gpg(homedir, IMPORT_OPTIONS + ['--import', attributes.path]), error: false)
            if result.exit_status != 0
              raise_command_failure("gpg import key: #{attributes.path}", unsupported_algorithm_note(attributes.path))
            end

            records = list_keys(homedir)
          }

          if records.empty?
            raise "no key could be read from #{attributes.path} (gpg cannot import a key that has no user id packet at all)"
          end

          record = records.detect {|r| r[:fingerprint] == desired.fingerprint }
          if record
            others = records.map {|r| r[:fingerprint] } - [record[:fingerprint]]
            unless others.empty?
              # Reads tolerate foreign keys in the file; writes never touch
              # such a file (see the guard below), so their presence is
              # only surfaced for diagnosis.
              MItamae.logger.debug "keyring also contains other keys: #{others.inspect}"
            end
            current.fingerprint = record[:fingerprint]
            verify_user_id(record[:uids], attributes.path)
            # Verification proved the exact match, so mirroring the desired
            # string keeps the comparison type-safe: an Array here against
            # the desired String would report a change on every run. Without
            # user_id the comparison is skipped (the desired side is nil)
            # and the full valid uid set is the honest current state.
            current.user_id = desired.user_id ? desired.user_id : record[:uids]
          else
            raise_if_sub_key_fingerprint(records, attributes.path)

            if records.length > 1
              # A fingerprint mismatch triggers a re-fetch that rewrites the
              # whole file, which would silently drop every other key kept
              # in it. This resource only ever writes single-key files.
              raise "#{attributes.path} contains multiple keys #{records.map {|r| r[:fingerprint] }.inspect} and none is #{desired.fingerprint}; refusing to rewrite the file"
            end

            # Single foreign key: adopt it as the current state so the
            # fingerprint mismatch triggers the usual re-fetch and
            # replacement. It is about to be replaced, so the user_id
            # assertion runs against the fetched key (pre_action) instead.
            current.fingerprint = records[0][:fingerprint]
            current.user_id = records[0][:uids].last
          end
          MItamae.logger.debug "fingerprint: #{current.fingerprint}"
        end

        def content_file
          @tempfile
        end

        def pre_action
          Dir.mktmpdir{|workdir|
            # desired.exist is false for the delete action: nothing to
            # fetch when the file is being removed.
            if desired.exist and ((!desired.content and !current.exist) or current.fingerprint != desired.fingerprint)
              # A homedir named by the recipe outlives the run and doubles
              # as a key store: when it already holds the pinned key there
              # is nothing to fetch, which is what makes the attribute
              # usable on hosts without network access. Refreshing such a
              # key is the homedir owner's job (drop it and run again) -
              # like an already-placed keyring file, it is never re-fetched
              # on its own.
              records = desired.homedir ? homedir_keys(desired.homedir) : []
              record = records.detect {|r| r[:fingerprint] == desired.fingerprint }

              if record
                homedir = desired.homedir
                source = desired.homedir
                MItamae.logger.debug "gpg key already in homedir: #{desired.homedir}"
              else
                # Fetching happens in a throwaway homedir even when the
                # recipe names one. What a URL or a keyserver hands over is
                # unverified until the checks below have run, and importing
                # it into the caller's keyring first would leave it there
                # whether or not it turns out to be the key that was asked
                # for. The downloaded file and the export output stay in
                # workdir for the same reason.
                homedir = File.join(workdir, 'gnupg')
                prepare_homedir(homedir)

                if desired.url
                  MItamae.logger.debug "gpg download url: #{desired.url}"

                  download = File.join(workdir, desired.fingerprint)

                  result = with_retry("gpg download key: url: #{desired.url}") {
                    run_command(['curl', '-fsSL', '-o', download, desired.url], error: false)
                  }
                  if result.exit_status != 0
                    raise MItamae::Backend::CommandExecutionError, "gpg download key: url: #{desired.url}"
                  end

                  result = run_command(gpg(homedir, IMPORT_OPTIONS + ['--import', download]), error: false)
                  if result.exit_status != 0
                    raise_command_failure("gpg import key: fingerprint: #{desired.fingerprint}", unsupported_algorithm_note(download))
                  end
                else
                  MItamae.logger.debug "gpg download keyserver: #{desired.keyserver}"

                  # The keyserver is passed on the command line rather than
                  # written to the homedir's gpg.conf, which --no-options
                  # ignores anyway.
                  #
                  # --recv-keys, not its --receive-keys alias: GnuPG 1.4
                  # only knows the short spelling, 2.x knows both.
                  result = with_retry("gpg receive key: keyserver: #{desired.keyserver}") {
                    run_command(gpg(homedir, KEYSERVER_IMPORT_OPTIONS + ['--keyserver', desired.keyserver, '--recv-keys', desired.fingerprint]), error: false)
                  }
                  if result.exit_status != 0
                    raise_command_failure("gpg receive key: keyserver: #{desired.keyserver} fingerprint: #{desired.fingerprint}", missing_ecc_note)
                  end
                end

                records = list_keys(homedir)
                source = desired.url ? desired.url : desired.keyserver
                record = records.detect {|r| r[:fingerprint] == desired.fingerprint }
              end

              # Verify the key before the export: a key that is not what the
              # recipe claims must never reach the target file.
              if record.nil?
                raise_if_sub_key_fingerprint(records, source)
                raise "gpg fetched key does not contain fingerprint #{desired.fingerprint}: got #{records.map {|r| r[:fingerprint] }.inspect} (#{source})"
              end
              verify_user_id(record[:uids], source)

              if File.extname(attributes.path).eql?('.gpg')
                opts = EXPORT_OPTIONS + ['--export', desired.fingerprint]
              else
                opts = EXPORT_OPTIONS + ['--export', '--armor', desired.fingerprint]
              end

              result = run_command(gpg(homedir, opts), error: false)
              if result.exit_status != 0
                raise MItamae::Backend::CommandExecutionError, "gpg export key: fingerprint: #{desired.fingerprint}"
              end

              Dir.mkdir(File.join(workdir, 'download'), 0755)
              File.open(File.join(workdir, 'download', desired.fingerprint), 'w') do |f|
                f.write(result.stdout)
              end
              @tempfile = File.join(workdir, 'download', desired.fingerprint)

              # What a recipe's homedir receives is the exported keyring
              # itself: verified, and stripped to the same self-signatures
              # the target file gets. Nothing reaches it that did not first
              # earn its way into the file.
              if desired.homedir and homedir != desired.homedir
                MItamae.logger.debug "gpg keep key in homedir: #{desired.homedir}"

                prepare_homedir(desired.homedir)

                result = run_command(gpg(desired.homedir, IMPORT_OPTIONS + ['--import', @tempfile]), error: false)
                if result.exit_status != 0
                  raise MItamae::Backend::CommandExecutionError, "gpg import key into homedir: #{desired.homedir}"
                end
              end
            end

            super
          }
        end
      end
    end
  end
end

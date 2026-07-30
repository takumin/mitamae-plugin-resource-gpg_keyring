# The CLI tools the pipeline shells out to are pinned in aqua.yaml and
# installed by `rake tool`. aqua exposes them through
# ${AQUA_ROOT_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/aquaproj-aqua}/bin,
# which has to be on PATH - the tasks below say so when it is not.
#
# aqua itself is not installed from here on purpose: bootstrapping a tool
# manager is the one thing the tool manager cannot do, and in CI it is the
# aqua-installer action's job.
module Tool
  INSTALL_DOCS = 'https://aquaproj.github.io/docs/install'
  PATH_HINT = 'export PATH="${AQUA_ROOT_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/aquaproj-aqua}/bin:$PATH"'.freeze

  module_function

  def which(command)
    ENV.fetch('PATH', '').split(File::PATH_SEPARATOR).each do |dir|
      candidate = File.join(dir, command)
      return candidate if File.file?(candidate) && File.executable?(candidate)
    end
    nil
  end

  # Resolves a tool that `rake tool` has installed, turning the bare
  # Errno::ENOENT you would get otherwise into the actual fix.
  def resolve(command)
    which(command) || raise(<<~MESSAGE)
      #{command} is not on PATH even though `aqua install` succeeded.
      aqua's bin directory is probably missing from PATH:

        #{PATH_HINT}
    MESSAGE
  end

  def aqua
    which('aqua') ||
      raise("aqua is not installed, and the CLI tools are pinned in aqua.yaml. See #{INSTALL_DOCS}")
  end
end

desc 'Install the pinned CLI tools (aqua.yaml)'
task :tool do
  # Idempotent: a no-op once every pinned version is present.
  sh Tool.aqua, 'install'
end

# Renovate bumps the versions in aqua.yaml but cannot compute the hashes
# that go with them, and `require_checksum` makes a stale checksum file a
# hard failure - so this is the one command that finishes such a PR.
desc 'Regenerate aqua-checksums.json for the versions pinned in aqua.yaml'
task :checksum do
  sh Tool.aqua, 'update-checksum', '-prune'
end

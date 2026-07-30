require 'rspec/core/rake_task'

desc 'Run the test suite (fully offline)'
RSpec::Core::RakeTask.new(:test)

# What a dependency bot changes but cannot finish: it raises versions and
# adds actions, leaving the hashes and the SHA pins to be derived. The
# autofix.ci workflow runs this on every pull request.
desc 'Regenerate the derived files (aqua checksums, action pins)'
task fix: %i[checksum pin]

desc 'Remove generated files (downloaded mitamae, temporary keyrings, ...)'
task :clean do
  sh 'git', 'clean', '-xdf'
end

# The full pipeline, identical to what CI runs (see .github/workflows/ci.yml).
task default: %i[lint test]

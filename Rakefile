require 'rspec/core/rake_task'

desc 'Run the test suite (fully offline)'
RSpec::Core::RakeTask.new(:test)

desc 'Remove generated files (downloaded mitamae, temporary keyrings, ...)'
task :clean do
  sh 'git', 'clean', '-xdf'
end

# The full pipeline, identical to what CI runs (see .github/workflows/ci.yml).
task default: %i[lint test]

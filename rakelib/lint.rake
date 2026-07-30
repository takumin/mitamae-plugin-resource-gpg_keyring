# Three angles on .github/workflows/, the one part of this repository no
# spec parses: actionlint asks whether it parses (handing `run:` blocks to
# the pinned shellcheck), zizmor whether it is safe, pinact whether every
# action is pinned to an immutable ref.
#
# zizmor runs --offline deliberately. Its online audits resolve action
# refs through the GitHub API, which would make the findings depend on
# whether the caller happens to hold a token; the pinning question they
# add is the one pinact answers anyway.
LINTERS = {
  'actionlint' => %w[-color],
  'zizmor' => %w[--offline .github/workflows],
  'pinact' => %w[run --check],
}.freeze

namespace :lint do
  LINTERS.each do |tool, args|
    desc "Lint the GitHub Actions workflows with #{tool}"
    task tool.to_sym => :tool do
      sh Tool.resolve(tool), *args
    end
  end
end

desc "Lint the GitHub Actions workflows (#{LINTERS.keys.join(', ')})"
task lint: :tool do
  # Every linter runs even after one has failed: a finding from one tool
  # should not hide the findings of the next.
  failed = LINTERS.keys.reject do |tool|
    Rake::Task["lint:#{tool}"].invoke
    true
  rescue RuntimeError
    false
  end
  raise "lint failed: #{failed.join(', ')}" unless failed.empty?
end

# The write side of `lint:pinact`, for the autofix.ci workflow and for
# whoever just added an action by tag.
desc 'Pin the actions in .github/workflows/ to commit SHAs (pinact)'
task pin: :tool do
  sh Tool.resolve('pinact'), 'run'
end

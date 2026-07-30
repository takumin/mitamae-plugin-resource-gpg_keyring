# Lints the GitHub Actions workflows, the one thing in this repository
# that no spec parses. actionlint (and the shellcheck it delegates `run:`
# blocks to) is pinned in aqua.yaml, so a laptop and CI report the same
# findings.
desc 'Lint the GitHub Actions workflows (actionlint)'
task lint: :tool do
  # No file arguments: actionlint discovers .github/workflows/ itself.
  sh Tool.resolve('actionlint'), '-color'
end

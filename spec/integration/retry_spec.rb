RSpec.describe 'network retries' do
  # Port 1 on localhost refuses immediately, so the example stays offline.
  it 'retries an unreachable keyserver with backoff before failing' do
    run = run_mitamae('keyserver_receive_retry')
    expect_mitamae_failure(run, %r{gpg receive key: keyserver: hkp://127\.0\.0\.1:1})
    # Three attempts mean exactly two backoff waits in the log.
    expect(run.log.scan('retrying in').size).to eq(2)
    expect(File.exist?(temporary('unreachable.gpg.asc'))).to be(false)
  end
end

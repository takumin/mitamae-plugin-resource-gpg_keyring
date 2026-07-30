RSpec.describe 'export-minimal' do
  it 'keeps only self-signatures in the placed keyring' do
    # The committed fixture must carry more than the self-signature,
    # otherwise this example cannot prove that export-minimal strips
    # anything.
    expect(signature_packet_count(fixture('third-party-signed.asc'))).to be >= 2

    run = run_mitamae('export_minimal')
    expect_mitamae_success(run)

    # Exactly one signature packet survives: the uid self-signature.
    expect(signature_packet_count(temporary('minimal.gpg.asc'))).to eq(1)
  end
end

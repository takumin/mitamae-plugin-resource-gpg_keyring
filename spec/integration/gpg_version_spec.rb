RSpec.describe 'gpg_keyring minimum gpg version' do
  # url_download_file_scheme is the cheapest recipe that runs the whole
  # fetch pipeline offline, so a success here means the version check let
  # a real run through rather than skipping everything.
  RECIPE = 'url_download_file_scheme'.freeze
  PLACED = 'file-url.gpg.asc'.freeze

  it 'refuses a gpg older than the minimum, naming the version' do
    with_gpg_stub('echo "gpg (GnuPG) 1.2.6"') do
      run = run_mitamae(RECIPE)
      expect_mitamae_failure(run, /`gpg` is 1\.2\.6, but .* needs GnuPG 1\.4\.3 or newer/)
      expect(File.exist?(temporary(PLACED))).to be(false)
    end
  end

  it 'reads the version from the GnuPG banner, not from a wrapper announcing itself first' do
    with_gpg_stub(%(echo "company-gpg 1.0"; exec #{GpgKeyringSpecHelper.real_gpg} --version)) do
      run = run_mitamae(RECIPE)
      expect_mitamae_success(run)
      expect(File.exist?(temporary(PLACED))).to be(true)
    end
  end

  it 'runs anyway when no recognizable banner is printed' do
    with_gpg_stub('echo "SomeVendor Crypto Suite"') do
      run = run_mitamae(RECIPE)
      expect_mitamae_success(run)
      expect(run.log).to include('skipping the minimum version check')
      expect(File.exist?(temporary(PLACED))).to be(true)
    end
  end
end

require 'webrick'

# A local HTTP server for the suite, serving the committed fixtures and
# doubling as an HKP keyserver: dirmngr fetches keys with
# GET /pks/lookup?op=get&...&search=0x<FPR>, which is plain HTTP, so the
# keyserver examples run offline against it.
#
# It listens on a fixed port so recipes can spell out the URL literally
# (recipes take no environment variables). If the port is taken, the
# suite fails fast with a clear error.
class LocalKeyServer
  def initialize(host, port, fixture_dir)
    @host = host
    @port = port
    @fixture_dir = fixture_dir
  end

  def start
    @server = WEBrick::HTTPServer.new(
      BindAddress: @host,
      Port: @port,
      Logger: WEBrick::Log.new(File::NULL),
      AccessLog: []
    )
    # HKP lookup (keyserver examples): always answers with the valid key.
    @server.mount_proc('/pks/lookup') do |_request, response|
      response['Content-Type'] = 'application/pgp-keys'
      response.body = File.binread(File.join(@fixture_dir, 'valid-key.asc'))
    end
    # Plain file download (url examples): serves the committed fixtures.
    @server.mount('/', WEBrick::HTTPServlet::FileHandler, @fixture_dir)
    @thread = Thread.new { @server.start }
  rescue Errno::EADDRINUSE
    raise "cannot start the local fixture server: #{@host}:#{@port} is already in use"
  end

  def stop
    @server&.shutdown
    @thread&.join
  end
end

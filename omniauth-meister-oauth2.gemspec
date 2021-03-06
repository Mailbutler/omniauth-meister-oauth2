
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "omniauth/meister_oauth2/version"

Gem::Specification.new do |spec|
  spec.name          = "omniauth-meister-oauth2"
  spec.version       = Omniauth::MeisterOauth2::VERSION
  spec.authors       = ["Honey Go"]
  spec.email         = ["honelyn@mailbutler.io"]

  spec.summary       = %q{ MindMeister Oauth2 strategy for Omniauth }
  spec.description   = %q{ MindMeister Oauth2 strategy for Omniauth. This allows you to authenticate to MindMeister from your ruby app. }
  spec.homepage      = 'https://github.com/Mailbutler/omniauth-meister-oauth2'
  spec.license       = 'MIT'

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the 'allowed_push_host'
  # to allow pushing to a single host or delete this section to allow pushing to any host.
  if spec.respond_to?(:metadata)
    spec.metadata["allowed_push_host"] = 'https://rubygems.org'
  else
    raise "RubyGems 2.0 or newer is required to protect against " \
      "public gem pushes."
  end

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files         = Dir.chdir(File.expand_path('..', __FILE__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.required_ruby_version = '>= 2.1'
  spec.add_runtime_dependency 'omniauth', '>= 1.1.1'
  spec.add_runtime_dependency 'omniauth-oauth2', '>= 1.3.1'
end

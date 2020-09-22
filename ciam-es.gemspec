$LOAD_PATH.push File.expand_path('../lib', __FILE__)

Gem::Specification.new do |s|
  s.name = 'ciam-es'
  s.version = '0.0.9'

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Fabiano Pavan"]
  s.date = Time.now.strftime("%Y-%m-%d")
  s.description = %q{SAML toolkit for Ruby programs to integrate with CIAM Milano }
  s.email = %q{fabiano.pavan@soluzionipa.it}
  s.files = `git ls-files`.split("\n")
  s.homepage = %q{https://github.com/EuroServizi/ciam-es}
  s.rdoc_options = ["--charset=UTF-8"]
  s.require_paths = ["lib"]
  s.summary = %q{SAML Ruby Tookit CIAM}
  s.license = "MIT"

  s.add_runtime_dependency("canonix", ["0.1.1"])
  s.add_runtime_dependency("uuid", ["~> 2.3"])
  s.add_runtime_dependency("nokogiri", '>= 1.6.7.2')
  s.add_runtime_dependency("addressable", [">= 2.4.0"])
end

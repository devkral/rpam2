Gem::Specification.new do |s|
  s.name = "rpam2"
  s.version = "4.0.1"
  s.date = "2018-03-23"
  s.summary = "PAM integration with ruby."
  s.email = "devkral@web.de"
  s.description = "Ruby PAM (Pluggable Authentication Modules) integration"
  s.extra_rdoc_files = ["README.rdoc"]
  s.authors = ["Alexander Kaftan"]
  s.files = ["lib/rpam2.rb", "ext/rpam2/rpam2.c", "ext/rpam2/extconf.rb", "rpam2.gemspec", "README.rdoc", "LICENSE.txt"]
  s.has_rdoc = true
  s.license = "MIT"
  s.homepage = "http://github.com/devkral/rpam2"
  s.require_paths = ["lib"]
  s.extensions = ["ext/rpam2/extconf.rb"]
end

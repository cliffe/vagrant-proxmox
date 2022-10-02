source 'https://rubygems.org'

group :development do
  # We depend on Vagrant for development, but we don't add it as a
  # gem dependency because we expect to be installed within the
  # Vagrant environment itself using `vagrant plugin`.
  gem 'vagrant', '2.3.1',
      git: 'https://github.com/mitchellh/vagrant.git',
      ref: 'v2.3.1'
  gem 'github_changelog_generator'
end

group :plugins do
  gemspec path: '.'
end

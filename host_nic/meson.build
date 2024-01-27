project('Host-Nic', 'c')
subdir('src')

deps = dependency('pcap')
includir = include_directories('include')

executable('hostnic', sources, dependencies: deps, include_directories: includir)
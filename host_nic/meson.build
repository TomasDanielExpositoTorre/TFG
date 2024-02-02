project('Host-Nic', 'c')
subdir('src')

deps = dependency('pcap')
includir = include_directories('include')

executable('hostnic-mono', sources_mono, dependencies: deps, include_directories: includir)
executable('hostnic-multi', sources_multi, dependencies: deps, include_directories: includir)
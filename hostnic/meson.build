project('Host-Nic', 'c')
subdir('src')

# add_global_arguments(['-D__OPTIMIZED', '-D__SIMSTORAGE'], language : 'c')
add_global_arguments(['-D__OPTIMIZED'], language : 'c')

deps = dependency('pcap')
includir = include_directories('include')

executable('hostnic-mono', sources_mono, dependencies: deps, include_directories: includir)
executable('hostnic-multi', sources_multi, dependencies: deps, include_directories: includir)

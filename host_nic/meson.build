project('Host-Nic', 'c')
subdir('src')

# add_global_arguments(['-D__OPTIMIZED', '-DNTHREADS=24'], language : 'c')
add_global_arguments(['-D__OPTIMIZED', '-D__SIMSTORAGE', '-DNTHREADS=8'], language : 'c')

deps = dependency('pcap')
includir = include_directories('include')

executable('hostnic-mono', sources_mono, dependencies: deps, include_directories: includir)
executable('hostnic-multi', sources_multi, dependencies: deps, include_directories: includir)
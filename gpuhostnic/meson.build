project('GPU-Host-Nic', 'cpp', 'cuda')
subdir('src')

deps = [dependency('cuda', version: '>= 11-8'), dependency('libdpdk')]
includir = include_directories('include')
add_project_arguments('-Wno-deprecated-declarations', language: 'cpp')

executable('gpu-hostnic', sources, dependencies: deps, include_directories: includir)

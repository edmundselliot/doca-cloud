project('doca-cloud', ['c','cpp'], default_options: ['buildtype=debug'])

add_project_arguments('-DDOCA_ALLOW_EXPERIMENTAL_API', language: ['c', 'cpp'])

samples_dir_path = '/opt/mellanox/doca/samples'
common_dir_path = '/opt/mellanox/doca/applications/common'

source_files = [
	'src/main.cpp',
    'src/app.cpp',
	'src/pipe_mgr.cpp',
    'src/control_path.cpp',
    'src/utils.cpp',
    samples_dir_path + '/common.c',
	common_dir_path + '/dpdk_utils.c',
]

deps = [
	dependency('doca-flow'),
	dependency('doca-common'),
	dependency('doca-dpdk-bridge'),
	dependency('libdpdk'),
]

app_inc_dirs = [
	include_directories('src'),
	include_directories(samples_dir_path),
	include_directories(samples_dir_path + '/doca_flow'),
	include_directories(common_dir_path),
]

executable(
	'doca-cloud',
	source_files,
	dependencies: deps,
	include_directories: app_inc_dirs
)

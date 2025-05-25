pkgdatadir = get_option('datadir') / meson.project_name()

gnome = import('gnome')
gnome.compile_resources('networkmap',
  'networkmap.gresource.xml',
  gresource_bundle: true,
  install: true,
  install_dir: pkgdatadir,
)

resource_path = join_paths(get_option('prefix'), 'share', 'networkmap', 'networkmap.gresource')
python = import('python')
py_installation = python.find_installation('python', required: true)

conf = configuration_data()
conf.set('PYTHON', 'python')
conf.set('VERSION', meson.project_version())
conf.set('localedir', get_option('localedir'))
conf.set('pkgdatadir', pkgdatadir)
conf.set('RESOURCE_PATH', resource_path)

configure_file(
  input: 'networkmap.in',
  output: 'networkmap',
  configuration: conf,
  install: true,
  install_dir: get_option('bindir'),
  install_mode: 'r-xr-xr-x'
)

networkmap_sources = [
  '__init__.py',
  'main.py',
  'window.py',
  'nmap_scanner.py',
  'preferences_window.py',
  'utils.py',
  'scan_page.py',
]

py_installation.install_sources(
  networkmap_sources,
  subdir: 'networkmap'
)

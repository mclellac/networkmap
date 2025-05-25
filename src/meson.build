pkgdatadir = get_option('prefix') / get_option('datadir') / meson.project_name()
moduledir = pkgdatadir
gnome = import('gnome')

gnome.compile_resources('networkmap',
  'networkmap.gresource.xml',
  gresource_bundle: true,
  install: true,
  install_dir: pkgdatadir,
)

python = import('python')

conf = configuration_data()
py_installation = python.find_installation('python3', required: true) # Added required: true for robustness
conf.set('PYTHON', py_installation.full_path())
conf.set('VERSION', meson.project_version())
conf.set('localedir', get_option('prefix') / get_option('localedir'))
conf.set('pkgdatadir', pkgdatadir)

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
  'utils.py', # Updated path
]

py_installation.install_sources(
  networkmap_sources,
  subdir: 'networkmap'
)

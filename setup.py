from setuptools import setup, find_packages

with open('requirements.txt', 'r') as fh:
    dependencies = [l.strip().split("#")[0] for l in fh]

standard_exclude = ('*.pyc', '*$py.class', '*~', '.*', '*.bak')
standard_exclude_directories = ('.*', 'CVS', '_darcs', './build', './dist', 'EGG-INFO', '*.egg-info')

setup(name='topka',
      version='1.0.0',
      description='A modular session manager for ogon',
      long_description=open('README.md').read(),
      author='David Fort',
      author_email='contact@hardening-consulting.com',
      url='https://github.com/hardening/topka',
      package_dir={'': 'src'},
      packages=find_packages('src', exclude=('tests',)),
      license='AGPL',
      keywords='ogon, session manager',
      install_requires=dependencies,
      # extras_require=extras,
      include_package_data=True,
      python_requires='>=3.4',
      entry_points={
          'console_scripts': [
                  'topkaLauncher = topka.remotelauncher:main',
                  'topka = topka.__main__:main',
                  'topka-cli = topka.topka_cli:main'
          ]
      },
)




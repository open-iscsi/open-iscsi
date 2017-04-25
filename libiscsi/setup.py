from distutils.core import setup, Extension

module1 = Extension('libiscsimodule',
                    sources = ['pylibiscsi.c'],
                    libraries = ['iscsi'],
                    library_dirs = ['.'])

setup (name = 'PyIscsi',version = '1.0',
       description = 'libiscsi python bindings', ext_modules = [module1])

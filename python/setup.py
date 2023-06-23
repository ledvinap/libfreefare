from setuptools import setup, Extension
from Cython.Build import cythonize
import os

nfc_inc = []
nfc_lib = []

nfc_path = os.environ.get('NFC_PATH')
if nfc_path is not None:
    nfc_inc.append(nfc_path + '/include')
    nfc_lib.append(nfc_path + '/lib')

freefare_ext = Extension(
    name                  = 'freefare',
    sources               = ['pyfreefare/freefare.pyx'],
    include_dirs          = ['../libfreefare'] + nfc_inc,
    library_dirs          = nfc_lib,
    runtime_library_dirs  = nfc_lib,
    libraries             = ['nfc','freefare'],
    extra_compile_args    = ["-O2", "-Wall"],
    language              = 'c'
)

nfc_ext = Extension(
    name                  = 'nfc',
    sources               = ['pyfreefare/nfc.pyx'],
    include_dirs          = nfc_inc,
    library_dirs          = nfc_lib,
    runtime_library_dirs  = nfc_lib,
    libraries             = ['nfc'],
    extra_compile_args    = ["-O2", "-Wall"],
    language              = 'c'
)

setup(
    ext_modules           = cythonize([freefare_ext, nfc_ext], annotate=True),
    packages              = ['pyfreefare'],
    package_data          = {'nfc': ['nfc.pxd']},
)


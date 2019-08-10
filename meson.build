project('mala_cryptor', 'c')
sodium_dep = dependency('libsodium')
#check for required system headers
compiler = meson.get_compiler('c')
if not compiler.has_header('getopt.h')
    error('Error! Getopt not found! Halting.')
endif
mala_cryptor_src = ['src/mala_cryptor.c', 'src/key_file.c', 'src/file_sym_enc.c']
c_flags = ['-O2', '-march=native']
executable('mala_cryptor',
           mala_cryptor_src,
           dependencies : sodium_dep,
           c_args : c_flags)

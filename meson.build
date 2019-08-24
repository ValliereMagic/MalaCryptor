project('mala_cryptor', 'c')
# Required system libraries
sodium_dep = dependency('libsodium')
openssl_dep = dependency('openssl')
# Link OQS based on the operating system we are building on
oqs_includes = '../lib/include'
oqs_link = '-loqs'
if (build_machine.system() == 'cygwin')
    frodo_dep = declare_dependency(include_directories: [oqs_includes], link_args: ['-L../lib/win', oqs_link])
elif (build_machine.system() == 'linux')
    frodo_dep = declare_dependency(include_directories: [oqs_includes], link_args: ['-L../lib/gnu_linux', oqs_link])
else
    error('Error! Not on a supported build platform. Halting.')
endif
# Check for required system headers
compiler = meson.get_compiler('c')
if not compiler.has_header('getopt.h')
    error('Error! Getopt not found! Halting.')
endif

# Make sure that the compiler has either of these headers.
if not compiler.has_header('winsock.h') and not compiler.has_header('arpa/inet.h')
    error('Error! Header for conversion to network byte order and back required! Halting.')
endif
# Build malacryptor executable
mala_cryptor_src = ['src/mala_cryptor.c', 'src/key_file.c', 'src/file_sym_enc.c']
c_flags = ['-O2', '-march=native']
executable('mala_cryptor',
           mala_cryptor_src,
           dependencies : [sodium_dep, openssl_dep, frodo_dep],
           c_args : c_flags)

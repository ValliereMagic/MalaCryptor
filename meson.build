project('mala_cryptor', 'c')
# Required system libraries
sodium_dep = dependency('libsodium')
openssl_dep = dependency('openssl')
check_dep = dependency('check')
# Link OQS based on the operating system we are building on
oqs_includes = include_directories(['../lib/include'])
oqs_link = '-loqs'
if (build_machine.system() == 'cygwin')
    oqs_dep = declare_dependency(include_directories: oqs_includes, link_args: ['-L../lib/win', oqs_link])
elif (build_machine.system() == 'linux')
    oqs_dep = declare_dependency(include_directories: oqs_includes, link_args: ['-L../lib/gnu_linux', oqs_link])
else
    error('Error! Not on a supported build platform. Halting.')
endif
# Check for required system headers
compiler = meson.get_compiler('c')
# Make sure that the compiler has either of these headers.
if not compiler.has_header('winsock.h') and not compiler.has_header('arpa/inet.h')
    error('Error! Header for conversion to network byte order and back required! Halting.')
endif
# Build malacryptor executable
mala_cryptor_src = ['src/mala_cryptor.c', 'src/key_file.c', 'src/file_sym_enc.c', 'src/key_derive.c', 'src/m_string.c']
c_flags = ['-O2', '-march=native']
deps = [sodium_dep, openssl_dep, oqs_dep]
executable('mala_cryptor',
           mala_cryptor_src,
           dependencies : deps,
           c_args : c_flags)

#Build Tests
test_deps = [sodium_dep, openssl_dep, oqs_dep, check_dep]
tests_c_flags = ['-g', '-march=native', '-I../src']
mala_cryptor_tests = executable('mala_cryptor_tests',
                                'tests/mala_cryptor-tests.c',
                                dependencies : test_deps,
                                c_args : tests_c_flags)

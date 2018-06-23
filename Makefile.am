#Include M4 Macros
ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = MalaCryptor

#Program Sources
MalaCryptor_SOURCES = \
    src/bin/MalaCryptor.c

#Link libsodium
MalaCryptor_LDADD = @WC_sodium_flags@

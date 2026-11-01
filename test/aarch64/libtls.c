/*
 * Thread-local storage the way a shared library reaches it on aarch64:
 * through TLS descriptors (GCC's default), through a static-TLS offset for a
 * variable declared initial-exec, and, in libtls-trad.c, through the module
 * and offset pairs `__tls_get_addr` takes. See test/README.md for the build.
 */
static __thread int counter = 5;        /* .tdata, local */
static __thread long scratch[3];        /* .tbss, local */
__thread long shared = 7;               /* .tdata, exported */
static __thread int fast
    __attribute__((tls_model("initial-exec"))) = 9; /* .tdata, static TLS */

/* One TLS descriptor per variable. */
int tls_get(void)
{
    return counter + (int)scratch[1] + (int)shared;
}

void tls_set(int x)
{
    counter = x;
    scratch[1] = x * 2;
    shared += x;
}

/* A static-TLS offset, loaded out of a GOT slot. */
int tls_fast(void)
{
    return fast++;
}

/* Built with -mtls-dialect=trad: see libtls.c. */
extern __thread long shared;
__thread int zeroed;                    /* .tbss, exported */

/* `__tls_get_addr` with the module and offset pair of each variable. */
long tls_trad(void)
{
    return shared + ++zeroed;
}

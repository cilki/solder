/* The second `pick`, and the global `scale`; see libstatics-a.c. */
__attribute__((noinline, noclone)) static int pick(int i)
{
    return i - 7;
}

int scale(int i)
{
    return i * 5;
}

int second(int i)
{
    return pick(i) * 2;
}

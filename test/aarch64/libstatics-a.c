/*
 * Two translation units that each define a `static` function called `pick`,
 * the way liblzma has a `coder_find` for its encoders and another for its
 * decoders (#124). This one also has a `static` `scale` that comes before the
 * global `scale` libstatics-b.c exports, since `.symtab` lists every local
 * ahead of the globals. See test/README.md.
 */
__attribute__((noinline, noclone)) static int pick(int i)
{
    return i + 1;
}

__attribute__((noinline, noclone)) static int scale(int i)
{
    return i * 3;
}

int first(int i)
{
    return pick(i) + scale(i);
}

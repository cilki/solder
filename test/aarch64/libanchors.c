/*
 * GCC's section anchors, which it turns on by default for aarch64 at -O1 and
 * above: `get` takes the address of `first` once and reaches `table` and
 * `last` as constant offsets from it, so nothing in its code names either of
 * them. `set` writes them so that they stay variables. Built *without*
 * -fno-section-anchors; see test/README.md.
 */
static int first = 1;
static int table[8] = {10, 20, 30, 40, 50, 60, 70, 80};
static int last = 3;

int get(int i)
{
    first += i;
    return first + table[i & 7] + last;
}

void set(int i, int v)
{
    table[i & 7] = v;
    last = v;
}

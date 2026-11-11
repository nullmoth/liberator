// nullmoth-safe-read <folder> <path below it> <max bytes> [head|tail]
//
// Prints at most <max bytes> of one file that lies below <folder>, from its start or its end (default: end).
// The log collector runs as root and reads files on a volume that other users can write to. A check for links
// followed by an ordinary read can be raced: the file is swapped for a link between the two. Here every part of
// the path is opened with "do not follow a link" relative to the folder opened before it, the last part must be
// a regular file with one name only, and the bytes are read from that same open file. Nothing is ever opened by
// its whole path. Exit 0: printed. Exit 1: not such a file inside the folder (a link, a hard link, a folder, missing).
// Exit 2: usage.
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 4 || argc > 5) { fprintf(stderr, "usage: nullmoth-safe-read <folder> <path below it> <max bytes> [head|tail]\n"); return 2; }
    const char *root = argv[1], *rel = argv[2];
    char *end = NULL; errno = 0;
    long long max = strtoll(argv[3], &end, 10);
    if (errno || !end || *end || max <= 0 || max > (64LL << 20)) { fprintf(stderr, "nullmoth-safe-read: bad size\n"); return 2; }
    int tail = 1;
    if (argc == 5) { if (!strcmp(argv[4], "head")) tail = 0; else if (strcmp(argv[4], "tail")) { fprintf(stderr, "nullmoth-safe-read: head or tail\n"); return 2; } }
    if (!*rel || rel[0] == '/' || strlen(rel) >= 4096) return 1;

    int dir = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir < 0) return 1;
    char buf[4096]; strlcpy(buf, rel, sizeof buf);
    char *save = NULL, *part = strtok_r(buf, "/", &save);
    int fd = -1;
    while (part) {
        char *next = strtok_r(NULL, "/", &save);
        if (!strcmp(part, ".") || !strcmp(part, "..")) { close(dir); return 1; }
        if (next) {
            int d = openat(dir, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            close(dir); if (d < 0) return 1; dir = d;
        } else {
            fd = openat(dir, part, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
            close(dir); if (fd < 0) return 1;
        }
        part = next;
    }
    if (fd < 0) return 1;
    struct stat st;
    // A regular file with exactly one name: a second name (a hard link) can make a file that only root may read
    // appear in a folder any user can write to, and "do not follow a link" does not see that.
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1) { close(fd); return 1; }
    off_t from = 0;
    if (tail && st.st_size > max) from = st.st_size - max;
    long long left = max; char io[65536];
    while (left > 0) {
        size_t want = left < (long long)sizeof io ? (size_t)left : sizeof io;
        ssize_t n = pread(fd, io, want, from);
        if (n <= 0) break;
        ssize_t off = 0;
        while (off < n) { ssize_t w = write(1, io + off, (size_t)(n - off)); if (w <= 0) { close(fd); return 0; } off += w; }
        from += n; left -= n;
    }
    close(fd);
    return 0;
}

/* Code to mangle pathnames into those matching a given prefix.
   eg. open("/lib/foo.so") => open("/usr/gnemul/i386-linux/lib/foo.so");

   The assumption is that this area does not change.
*/
#include "qemu/osdep.h"
#include <sys/param.h>
#include <dirent.h>
#include "qemu/cutils.h"
#include "qemu/path.h"
#include "qemu/thread.h"

#define SYMLOOP_MAX 40

static const char* base;
static GHashTable* hash;
static QemuMutex lock;

void init_paths(const char* prefix)
{
    if (prefix[0] == '\0' || !strcmp(prefix, "/")) {
        return;
    }

    char* tmp_base;
    if (prefix[0] == '/') {
        tmp_base = g_strdup(prefix);
    }
    else {
        char* cwd = g_get_current_dir();
        tmp_base = g_build_filename(cwd, prefix, NULL);
        g_free(cwd);
    }
    char real[PATH_MAX];
    realpath(tmp_base, real);
    g_free(tmp_base);
    base = g_strdup(real);

    hash = g_hash_table_new(g_str_hash, g_str_equal);
    qemu_mutex_init(&lock);
}

static bool skip_relocation(const char* name)
{
    return strstr(name, "/proc/") == name
        || strcmp(name, "/proc") == 0
        || strstr(name, "/sys/") == name
        || strcmp(name, "/sys") == 0
        || strcmp(name, "/etc/resolv.conf") == 0
        || strcmp(name, "/dev") == 0
        || strstr(name, "/dev/") == name
    ;
}

const char* do_relocate_path(const char* guest, char* out)
{
    if (!base || !guest) {
        //  invalid
        goto use_original;
    }
    if (skip_relocation(guest)) {
        //  reuse hosts
        goto use_original;
    }
    if (strstr(guest, base) == guest) {
        //  already at rootfs
        goto use_original;
    }

    char host_path[PATH_MAX];
    if (guest[0] != '/') {
        //  relative to absolute
        getcwd(host_path, sizeof(host_path));
        strcat(host_path, "/");
        strcat(host_path, guest);
    }
    else {
        if (strcmp(guest, "/mnt/host-root") == 0) {
            //  root of host
            strcpy(host_path, "/");
        }
        else if (strstr(guest, "/mnt/host-root/") == guest) {
            //  remove prefix
            strcpy(host_path, guest + strlen("/mnt/host-root"));
        }
        else {
            //  absolute
            strcpy(host_path, base);
            strcat(host_path, "/");
            strcat(host_path, guest);
        }
    }

    strcpy(out, host_path);
    return out;

use_original:
    strcpy(out, guest);
    return out;
}

static bool convert_to_abs_path(int host_dirfd, const char* guest_path, char* out)
{
    if (host_dirfd == AT_FDCWD || guest_path[0] == '/') {
        do_relocate_path(guest_path, out);
        return true;
    }

    char self_fd[PATH_MAX];
    snprintf(self_fd, sizeof(self_fd), "/proc/self/fd/%d", host_dirfd);
    char host_path[PATH_MAX] = {0};
    ssize_t len = readlink(self_fd, host_path, sizeof(host_path) - 1);
    if (len <= 0) {
        return false;
    }
    host_path[len] = '\0';

    if (strstr(host_path, base) != &host_path[0]) {
        //  not in base
        char host_full_path[PATH_MAX];
        snprintf(host_full_path, sizeof(host_full_path), "%s/%s", host_path, guest_path);
        return true;
    }

    char host_full_path[PATH_MAX];
    snprintf(host_full_path, sizeof(host_full_path), "%s/%s", host_path, guest_path);
    do_relocate_path(host_full_path, out);
    return true;
}

static size_t slash_len(const char* s)
{
    const char* s0 = s;
    while (*s == '/') s++;
    return s - s0;
}

static char* str_chrnul(const char* s, int c)
{
    c = (unsigned char)c;
    if (!c) return (char*)s + strlen(s);

    for (; *s && *(unsigned char*)s != c; s++);
    return (char*)s;
}

ssize_t readlink_with_relocation(char* path, char* buf, size_t len)
{
    char tmp[PATH_MAX];
    ssize_t ret = readlink(path, tmp, PATH_MAX - 1);
    if (ret < 0) {
        return ret;
    }
    tmp[ret] = '\0';
    if (tmp[0] != '/') {
        strncpy(buf, tmp, len);
    }
    else {
        char abs[PATH_MAX];
        do_relocate_path(tmp, abs);
        strncpy(buf, abs, len);
    }
    return strlen(buf);
}

/**
 * copy and modify from realpath of musl
 */
char* readpath_with_relocation(const char* restrict filename, char* restrict resolved)
{
    char stack[PATH_MAX + 1];
    char output[PATH_MAX];
    size_t p, q, l, l0, cnt = 0, nup = 0;
    int check_dir = 0;

    if (!filename) {
        errno = EINVAL;
        return 0;
    }
    l = strnlen(filename, sizeof stack);
    if (!l) {
        errno = ENOENT;
        return 0;
    }
    if (l >= PATH_MAX) goto toolong;
    p = sizeof stack - l - 1;
    q = 0;
    memcpy(stack + p, filename, l + 1);

    /* Main loop. Each iteration pops the next part from stack of
     * remaining path components and consumes any slashes that follow.
     * If not a link, it's moved to output; if a link, contents are
     * pushed to the stack. */
restart:
    for (; ; p += slash_len(stack + p)) {
        /* If stack starts with /, the whole component is / or //
         * and the output state must be reset. */
        if (stack[p] == '/') {
            check_dir = 0;
            nup = 0;
            q = 0;
            output[q++] = '/';
            p++;
            /* Initial // is special. */
            if (stack[p] == '/' && stack[p + 1] != '/')
                output[q++] = '/';
            continue;
        }

        char* z = str_chrnul(stack + p, '/');
        l0 = l = z - (stack + p);

        if (!l && !check_dir) break;

        /* Skip any . component but preserve check_dir status. */
        if (l == 1 && stack[p] == '.') {
            p += l;
            continue;
        }

        /* Copy next component onto output at least temporarily, to
         * call readlink, but wait to advance output position until
         * determining it's not a link. */
        if (q && output[q - 1] != '/') {
            if (!p) goto toolong;
            stack[--p] = '/';
            l++;
        }
        if (q + l >= PATH_MAX) goto toolong;
        memcpy(output + q, stack + p, l);
        output[q + l] = 0;
        p += l;

        int up = 0;
        if (l0 == 2 && stack[p - 2] == '.' && stack[p - 1] == '.') {
            up = 1;
            /* Any non-.. path components we could cancel start
             * after nup repetitions of the 3-byte string "../";
             * if there are none, accumulate .. components to
             * later apply to cwd, if needed. */
            if (q <= 3 * nup) {
                nup++;
                q += l;
                continue;
            }
            /* When previous components are already known to be
             * directories, processing .. can skip readlink. */
            if (!check_dir) goto skip_readlink;
        }
        ssize_t k = readlink_with_relocation(output, stack, p);

        if (k == p) goto toolong;
        if (!k) {
            errno = ENOENT;
            return 0;
        }
        if (k < 0) {
            if (errno != EINVAL) return 0;
        skip_readlink:
            check_dir = 0;
            if (up) {
                while (q && output[q - 1] != '/') q--;
                if (q > 1 && (q > 2 || output[0] != '/')) q--;
                continue;
            }
            if (l0) q += l;
            check_dir = stack[p];
            continue;
        }
        if (++cnt == SYMLOOP_MAX) {
            errno = ELOOP;
            return 0;
        }

        /* If link contents end in /, strip any slashes already on
         * stack to avoid /->// or //->/// or spurious toolong. */
        if (stack[k - 1] == '/') while (stack[p] == '/') p++;
        p -= k;
        memmove(stack + p, stack, k);

        /* Skip the stack advancement in case we have a new
         * absolute base path. */
        goto restart;
    }

    output[q] = 0;

    if (output[0] != '/') {
        if (!getcwd(stack, sizeof stack)) return 0;
        l = strlen(stack);
        /* Cancel any initial .. components. */
        p = 0;
        while (nup--) {
            while (l > 1 && stack[l - 1] != '/') l--;
            if (l > 1) l--;
            p += 2;
            if (p < q) p++;
        }
        if (q - p && stack[l - 1] != '/') stack[l++] = '/';
        if (l + (q - p) + 1 >= PATH_MAX) goto toolong;
        memmove(output + l, output + p, q - p + 1);
        memcpy(output, stack, l);
        q = l + q - p;
    }

    if (resolved) return memcpy(resolved, output, q + 1);
    else return strdup(output);

toolong:
    errno = ENAMETOOLONG;
    return 0;
}

static bool real_exists(const char* path)
{
    struct stat s;
    if (lstat(path, &s) < 0) {
        return false;
    }
    return !S_ISLNK(s.st_mode);
}

char* relocate_path_at(int host_dirfd, const char* guest_path, char* out, bool follow_symlink)
{
    char host_full_path[PATH_MAX];
    convert_to_abs_path(host_dirfd, guest_path, host_full_path);

    if (follow_symlink
        && !skip_relocation(guest_path)
        && !real_exists(host_full_path)) {
        char* res = readpath_with_relocation(host_full_path, out);
        if (!res) {
            strcpy(out, host_full_path);
        }
    }
    else {
        strcpy(out, host_full_path);
    }

    return out;
}

char* restore_path(const char* host_path, char* out)
{
    if (host_path[0] != '/') {
        goto reuse;
    }

    char buf_base[PATH_MAX];
    strcpy(buf_base, base);
    int len = strlen(buf_base);
    if (len == 0 || buf_base[len - 1] != '/') {
        strcat(buf_base, "/");
    }

    if (strstr(host_path, buf_base) == host_path) {
        strcpy(out, host_path + strlen(buf_base) - 1);
    }
    else {
        //  not in base
        sprintf(out, "/mnt/host-root/%s", host_path);
    }
    return out;

reuse:
    strcpy(out, host_path);
    return out;
}

char* resolve_with_path_env(const char* path_env, int dirfd, const char* name, char* out)
{
    if (!path_env || !name || !out) return NULL;

    char* path_copy = strdup(path_env);
    if (!path_copy) return NULL;

    char reloc[PATH_MAX];
    const int r = access(relocate_path_at(dirfd, name, reloc, true), F_OK);
    if (r == 0) {
        strncpy(out, name, PATH_MAX);
        return out;
    }

    char* ret = NULL;

    qemu_mutex_lock(&lock);

    char* dir = strtok(path_copy, ":");
    char full_path[PATH_MAX];

    while (dir) {
        snprintf(full_path, sizeof(full_path), "%s/%s", dir, name);

        const int r = access(relocate_path_at(AT_FDCWD, full_path, reloc, true), F_OK);
        if (r == 0) {
            strncpy(out, full_path, PATH_MAX);
            ret = out;
            break;
        }

        dir = strtok(NULL, ":");
    }

    qemu_mutex_unlock(&lock);

    free(path_copy);
    return ret;
}

char* resolve_abs_with_cwd(const char* path, char* out)
{
    if (path[0] != '/') {
        char* cwd = g_get_current_dir();
        char* abs_base = g_build_filename(cwd, path, NULL);
        strcpy(out, abs_base);
        g_free(cwd);
        g_free(abs_base);
        return out;
    }
    else {
        strcpy(out, path);
        return out;
    }
}

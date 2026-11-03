/*
  zip_modify_fuzzer.c -- fuzz modifying and rewriting an untrusted archive
  Copyright (C) 2026 The libzip Authors

  SPDX-License-Identifier: BSD-3-Clause

  Coverage gap addressed:
    The read fuzzers open an untrusted archive and only consume it.
    zip_write_roundtrip_fuzzer modifies archives, but always starts from an
    empty archive, so every entry it serializes was created by libzip itself.
    No harness takes an *untrusted* archive, changes it and writes it back,
    which is what any application that updates a user-supplied ZIP does.
    The following paths were therefore not reached:

      - _zip_checkcons() / _zip_headercomp() (zip_open() with ZIP_CHECKCONS),
        which parse every local file header and compare it to the central
        directory
      - the zip_close() copy path for unchanged entries: _zip_file_get_offset(),
        copy_data(), data-descriptor rewriting, _zip_dirent_write() of
        parsed (attacker-controlled) dirents and extra fields
      - recompression / re-encryption of existing entries via
        zip_source_zip_file_create() (zip_source_zip_new.c,
        zip_source_window.c)
      - copying entries, raw or decompressed, partially or completely, from
        another untrusted archive with zip_source_zip_file()
      - zip_unchange(), zip_file_replace(), zip_file_set_dostime(),
        zip_file_set_external_attributes(), zip_file_extra_field_delete()

  Input layout:
    The last byte N gives the length of a control block made of the N bytes
    before it; everything in front of the control block is the archive.
    The control bytes select open flags and a sequence of modification
    operations.  After zip_close() the rewritten archive is reopened with
    ZIP_CHECKCONS and every entry is read back.
*/

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <zip.h>

#define MAX_OPS 32
#define MAX_COPY_LENGTH 65536

typedef struct {
    const uint8_t *p;
    size_t len;
    size_t pos;
} stream_t;

static uint8_t
u8(stream_t *s) {
    return s->pos < s->len ? s->p[s->pos++] : 0;
}

static uint16_t
u16(stream_t *s) {
    uint16_t v = u8(s);
    v = (uint16_t)(v | ((uint16_t)u8(s) << 8));
    return v;
}

static uint32_t
u32(stream_t *s) {
    uint32_t v = u16(s);
    v |= (uint32_t)u16(s) << 16;
    return v;
}

static const char *PASSWORD = "secretpassword";

static void
read_all(zip_t *za) {
    zip_int64_t n, i;
    char buf[8192];

    n = zip_get_num_entries(za, 0);
    for (i = 0; i < n; i++) {
        zip_stat_t st;
        zip_file_t *f;

        zip_stat_init(&st);
        (void)zip_stat_index(za, (zip_uint64_t)i, 0, &st);

        if ((f = zip_fopen_index(za, (zip_uint64_t)i, 0)) == NULL) {
            continue;
        }
        while (zip_fread(f, buf, sizeof(buf)) > 0) {
            ;
        }
        zip_fclose(f);
    }
}

static zip_t *
open_buffer(const uint8_t *data, size_t size, int flags, zip_source_t **srcp) {
    zip_error_t error;
    zip_source_t *src;
    zip_t *za;

    zip_error_init(&error);
    if ((src = zip_source_buffer_create(data, size, 0, &error)) == NULL) {
        zip_error_fini(&error);
        return NULL;
    }
    if ((za = zip_open_from_source(src, flags, &error)) == NULL) {
        zip_source_free(src);
        zip_error_fini(&error);
        return NULL;
    }
    zip_error_fini(&error);
    if (srcp) {
        *srcp = src;
    }
    return za;
}

#ifdef __cplusplus
extern "C" {
#endif

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const zip_int32_t methods[] = {ZIP_CM_DEFAULT, ZIP_CM_STORE, ZIP_CM_DEFLATE, ZIP_CM_BZIP2, ZIP_CM_XZ, ZIP_CM_ZSTD};
    static const zip_uint16_t encryptions[] = {ZIP_EM_NONE, ZIP_EM_TRAD_PKWARE, ZIP_EM_AES_128, ZIP_EM_AES_256};
    stream_t ctl;
    size_t ctl_len, archive_len;
    zip_source_t *src = NULL;
    zip_t *za, *other;
    zip_int64_t n;
    int open_flags, nops, i;
    uint8_t mode;

    if (size == 0) {
        return 0;
    }
    ctl_len = data[size - 1];
    if (ctl_len > size - 1) {
        ctl_len = size - 1;
    }
    archive_len = size - 1 - ctl_len;
    ctl.p = data + archive_len;
    ctl.len = ctl_len;
    ctl.pos = 0;

    mode = u8(&ctl);
    open_flags = (mode & 1) ? ZIP_CHECKCONS : 0;

    if ((za = open_buffer(data, archive_len, open_flags, &src)) == NULL) {
        return 0;
    }
    /* Keep the buffer alive across zip_close() so it can be reopened. */
    zip_source_keep(src);
    zip_set_default_password(za, PASSWORD);

    /* A second, independent read-only view of the same untrusted archive to
       copy entries from. */
    other = open_buffer(data, archive_len, ZIP_RDONLY | ((mode & 2) ? ZIP_CHECKCONS : 0), NULL);
    if (other) {
        zip_set_default_password(other, PASSWORD);
    }

    nops = (int)(u8(&ctl) % MAX_OPS) + 1;
    for (i = 0; i < nops && ctl.pos < ctl.len; i++) {
        uint8_t op = u8(&ctl) % 12;
        zip_uint64_t idx;

        n = zip_get_num_entries(za, 0);
        idx = n > 0 ? u16(&ctl) % (zip_uint64_t)n : 0;

        switch (op) {
        case 0: /* recompress an existing entry */
            if (n > 0) {
                zip_set_file_compression(za, idx, methods[u8(&ctl) % (sizeof(methods) / sizeof(methods[0]))], u8(&ctl) % 10);
            }
            break;

        case 1: /* re-encrypt (or decrypt) an existing entry */
            if (n > 0) {
                zip_file_set_encryption(za, idx, encryptions[u8(&ctl) % (sizeof(encryptions) / sizeof(encryptions[0]))], PASSWORD);
            }
            break;

        case 2:
            if (n > 0) {
                zip_delete(za, idx);
            }
            break;

        case 3: {
            char name[16];
            memcpy(name, "renamed-", 8);
            name[8] = (char)('a' + u8(&ctl) % 26);
            name[9] = (char)('a' + u8(&ctl) % 26);
            name[10] = '\0';
            if (n > 0) {
                zip_file_rename(za, idx, name, 0);
            }
            break;
        }

        case 4:
            if (n > 0) {
                zip_file_set_dostime(za, idx, u16(&ctl), u16(&ctl), 0);
            }
            break;

        case 5:
            if (n > 0) {
                zip_file_set_external_attributes(za, idx, 0, u8(&ctl), u32(&ctl));
            }
            break;

        case 6: { /* set or delete an extra field */
            zip_flags_t where = (u8(&ctl) & 1) ? ZIP_FL_LOCAL : ZIP_FL_CENTRAL;
            if (n <= 0) {
                break;
            }
            if (u8(&ctl) & 1) {
                zip_uint8_t ef[32];
                zip_uint16_t eflen = u8(&ctl) % sizeof(ef);
                memset(ef, u8(&ctl), eflen);
                zip_file_extra_field_set(za, idx, u16(&ctl), ZIP_EXTRA_FIELD_NEW, ef, eflen, where);
            }
            else {
                zip_file_extra_field_delete(za, idx, ZIP_EXTRA_FIELD_ALL, where);
            }
            break;
        }

        case 7: {
            zip_uint8_t c[16];
            zip_uint16_t clen = u8(&ctl) % sizeof(c);
            memset(c, 'A' + u8(&ctl) % 26, clen);
            if (n > 0 && (u8(&ctl) & 1)) {
                zip_file_set_comment(za, idx, (const char *)c, clen, 0);
            }
            else {
                zip_set_archive_comment(za, (const char *)c, clen);
            }
            break;
        }

        case 8: /* copy an entry (or part of it) from the other archive */
        case 9: {
            zip_int64_t on;
            zip_uint64_t oidx, start = 0;
            zip_int64_t len = -1;
            zip_flags_t flags = 0;
            zip_source_t *zs;
            uint8_t f;
            char name[16];

            if (other == NULL || (on = zip_get_num_entries(other, 0)) <= 0) {
                break;
            }
            oidx = u16(&ctl) % (zip_uint64_t)on;
            f = u8(&ctl);
            if (f & 1) {
                flags |= ZIP_FL_COMPRESSED;
            }
            if (f & 2) {
                start = u16(&ctl);
                len = (zip_int64_t)(u16(&ctl) % MAX_COPY_LENGTH);
            }
            if ((zs = zip_source_zip_file(za, other, oidx, flags, start, len, (f & 4) ? PASSWORD : NULL)) == NULL) {
                break;
            }
            if (op == 9 && n > 0) {
                if (zip_file_replace(za, idx, zs, 0) < 0) {
                    zip_source_free(zs);
                }
            }
            else {
                memcpy(name, "copy-", 5);
                name[5] = (char)('a' + u8(&ctl) % 26);
                name[6] = (char)('a' + u8(&ctl) % 26);
                name[7] = '\0';
                if (zip_file_add(za, name, zs, ZIP_FL_OVERWRITE) < 0) {
                    zip_source_free(zs);
                }
            }
            break;
        }

        case 10:
            if (n > 0) {
                zip_unchange(za, idx);
            }
            break;

        case 11:
            if (u8(&ctl) & 1) {
                zip_unchange_archive(za);
            }
            else {
                zip_unchange_all(za);
            }
            break;
        }
    }

    /* Serialize the modified archive back into the buffer source. */
    if (zip_close(za) < 0) {
        zip_discard(za);
        if (other) {
            zip_discard(other);
        }
        zip_source_free(src); /* release keep reference */
        return 0;
    }
    if (other) {
        zip_discard(other);
    }

    /* Reopen what was written, strictly, and read everything back. */
    zip_source_keep(src);
    {
        zip_error_t error;
        zip_error_init(&error);
        za = zip_open_from_source(src, ZIP_RDONLY | ZIP_CHECKCONS, &error);
        zip_error_fini(&error);
    }
    if (za == NULL) {
        zip_source_free(src); /* undo the keep above */
    }
    else {
        zip_set_default_password(za, PASSWORD);
        read_all(za);
        zip_discard(za);
    }
    zip_source_free(src); /* release keep reference */
    return 0;
}

#ifdef __cplusplus
}
#endif

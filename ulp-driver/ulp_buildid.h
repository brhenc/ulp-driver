/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * ulp_buildid.h - read the GNU build-id note of an ELF64 file (userspace).
 * The driver compares it at exec time against the build-id stored in a
 * persistent rule, so rules made for an older build of a binary are skipped.
 */
#ifndef _ULP_BUILDID_H
#define _ULP_BUILDID_H

#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef NT_GNU_BUILD_ID
#define NT_GNU_BUILD_ID 3
#endif

/* Returns the build-id length (1..max), 0 if the file has none, or -1 on error. */
static inline int ulp_read_build_id(const char *path, uint8_t *id, size_t max)
{
	Elf64_Ehdr eh;
	int fd, ret = 0;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	if (pread(fd, &eh, sizeof(eh), 0) != sizeof(eh) ||
	    memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 || eh.e_ident[EI_CLASS] != ELFCLASS64 ||
	    eh.e_phentsize != sizeof(Elf64_Phdr) || eh.e_phnum > 128) {
		close(fd);
		return -1;
	}

	for (int i = 0; i < eh.e_phnum && ret == 0; i++) {
		Elf64_Phdr ph;
		uint8_t buf[4096];
		ssize_t n;
		size_t off = 0;

		if (pread(fd, &ph, sizeof(ph), eh.e_phoff + (uint64_t)i * sizeof(ph)) != sizeof(ph)) {
			ret = -1;
			break;
		}
		if (ph.p_type != PT_NOTE)
			continue;
		n = pread(fd, buf, ph.p_filesz < sizeof(buf) ? ph.p_filesz : sizeof(buf), ph.p_offset);
		while (n > 0 && off + sizeof(Elf64_Nhdr) <= (size_t)n) {
			Elf64_Nhdr *nh = (Elf64_Nhdr *)(buf + off);
			size_t name_off = off + sizeof(*nh);
			size_t desc_off = name_off + ((nh->n_namesz + 3) & ~3u);
			size_t next = desc_off + ((nh->n_descsz + 3) & ~3u);

			if (next > (size_t)n || next <= off)
				break;
			if (nh->n_type == NT_GNU_BUILD_ID && nh->n_namesz == 4 &&
			    memcmp(buf + name_off, "GNU", 4) == 0 &&
			    nh->n_descsz > 0 && nh->n_descsz <= max) {
				memcpy(id, buf + desc_off, nh->n_descsz);
				ret = (int)nh->n_descsz;
				break;
			}
			off = next;
		}
	}
	close(fd);
	return ret;
}

static inline void ulp_build_id_to_hex(const uint8_t *id, int len, char *out)
{
	for (int i = 0; i < len; i++)
		sprintf(out + 2 * i, "%02x", id[i]);
	out[2 * (len > 0 ? len : 0)] = '\0';
}

/* Parses a hex build-id. Returns its length in bytes, or -1 if invalid. */
static inline int ulp_build_id_from_hex(const char *hex, uint8_t *id, size_t max)
{
	size_t len = strlen(hex);

	if (len == 0 || len % 2 || len / 2 > max)
		return -1;
	for (size_t i = 0; i < len / 2; i++) {
		unsigned int b;

		if (sscanf(hex + 2 * i, "%2x", &b) != 1)
			return -1;
		id[i] = (uint8_t)b;
	}
	return (int)(len / 2);
}

#endif /* _ULP_BUILDID_H */

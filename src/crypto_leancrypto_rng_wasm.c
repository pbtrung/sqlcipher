/*
** SQLCipher
** http://sqlcipher.net
**
** Copyright (c) 2008 - 2013, ZETETIC LLC
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions are met:
**     * Redistributions of source code must retain the above copyright
**       notice, this list of conditions and the following disclaimer.
**     * Redistributions in binary form must reproduce the above copyright
**       notice, this list of conditions and the following disclaimer in the
**       documentation and/or other materials provided with the distribution.
**     * Neither the name of the ZETETIC LLC nor the
**       names of its contributors may be used to endorse or promote products
**       derived from this software without specific prior written permission.
**
** THIS SOFTWARE IS PROVIDED BY ZETETIC LLC ''AS IS'' AND ANY
** EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
** WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL ZETETIC LLC BE LIABLE FOR ANY
** DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
** (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
** LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
** ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
** SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**
*/
/*
** WASM entropy source for the vendored leancrypto submodule (see
** third_party/leancrypto and wasm/README.md).
**
** Adapted from smuellerDD/leancrypto's own reference WASM build at
** https://github.com/pbtrung/secbits/blob/main/leancrypto/seeded_rng_wasm.c
** (same license terms as the rest of leancrypto: 2-clause BSD, see
** third_party/leancrypto/LICENSE.bsd).
**
** leancrypto's own drng/src/seeded_rng.c calls out to four extern C
** functions -- get_full_entropy(), seeded_rng_noise_init(),
** seeded_rng_noise_fini(), seeded_rng_status() -- that are normally
** supplied by an OS-specific backend file (seeded_rng_linux.c,
** seeded_rng_bsd.c, seeded_rng_darwin.c, seeded_rng_windows.c); there is
** no such file for host_machine.system() == 'emscripten'. This file
** supplies them for the WASM build, so linking succeeds if anything
** inside leancrypto ever references seeded_rng.c's symbols.
**
** NOTE: in this project's actual Meson configuration (see
** LEANCRYPTO_MESON_OPTS in main.mk and tool/build-wasm.sh), none of the
** DRNG options that cause seeded_rng.c itself to be compiled in
** (xdrbg, kmac_drng, cshake_drng, drbg_hash, drbg_ctr) are enabled, on
** either the native or the WASM build -- src/crypto_leancrypto.c never
** calls into leancrypto's own RNG at all, using getrandom(2) (native) or
** getentropy() (WASM) directly instead (see the comment on
** sqlcipher_leancrypto_random() in src/crypto_leancrypto.c for why).
** So this file is not currently exercised by anything; it is vendored
** anyway, purely defensively, to match the reference build and in case
** that ever changes.
**
** get_full_entropy() delegates to Emscripten's getentropy() libc shim,
** which is backed by the browser's crypto.getRandomValues() or Node's
** crypto.randomFillSync(). getentropy() is capped at 256 bytes per call
** (POSIX requirement), hence the chunking loop.
*/
#ifdef __EMSCRIPTEN__
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h> /* getentropy() via the Emscripten sysroot */
#include "lc_memcpy_secure.h"

ssize_t get_full_entropy(uint8_t *buffer, size_t bufferlen)
{
	size_t offset = 0;

	while (offset < bufferlen) {
		/* getentropy() is limited to 256 bytes per call */
		size_t chunk = bufferlen - offset;

		if (chunk > 256)
			chunk = 256;

		if (getentropy(buffer + offset, chunk) != 0)
			return -1;

		offset += chunk;
	}

	return (ssize_t)bufferlen;
}

void seeded_rng_noise_fini(void)
{
	/* No noise source to clean up in WASM */
}

int seeded_rng_noise_init(void)
{
	/* No noise source to initialize in WASM */
	return 0;
}

void seeded_rng_status(char *buf, size_t len)
{
	lc_memcpy_secure(buf, len, "Emscripten getentropy\n\0", 22);
}
#endif /* __EMSCRIPTEN__ */

// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * Host test of the kernel's instruction emulator (patches/xnu-12377/nopac-emulate.patch,
 * osfmk/arm64/nopac_emulate.c). Encodings are llvm-mc's. Run by test_emulate.py.
 */
#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <arm64/nopac_emulate.h>

static uint64_t memory[8];
static const uint64_t memory_base = 0x10000;

static int
load(void *cookie, uint64_t address, uint64_t *value)
{
	(void)cookie;
	if (address < memory_base || address >= memory_base + sizeof(memory) || (address & 7)) {
		return -1;
	}
	*value = memory[(address - memory_base) / 8];
	return 0;
}

static struct nopac_context
fresh(void)
{
	struct nopac_context c;

	memset(&c, 0, sizeof(c));
	for (unsigned i = 0; i < 31; i++) {
		c.x[i] = 0x1000 + i;
	}
	c.sp = memory_base + 16;
	c.pc = 0x4000;
	c.has_fp = true;
	c.load64 = load;
	return c;
}

#define RUN(word) assert(nopac_emulate_instruction((word), &c) == NOPAC_DONE)

static uint32_t
fjcvtzs(double value, uint32_t *flags)
{
	struct nopac_context c = fresh();

	memcpy(&c.d[2], &value, sizeof(value));
	c.nzcv = 0xF0000000u;
	RUN(0x1E7E0041u);       /* fjcvtzs w1, d2 */
	*flags = c.nzcv;
	return (uint32_t)c.x[1];
}

int
main(void)
{
	struct nopac_context c;
	uint32_t flags;

	for (unsigned i = 0; i < 8; i++) {
		memory[i] = 0xAA00 + i;
	}

	/* PAC*, AUT*, XPAC*: no change but the pc */
	static const uint32_t nops[] = { 0xDAC10041u /* pacia x1, x2 */, 0xDAC11FE3u /* autdb x3, sp */,
		                         0xDAC123E4u /* paciza x4 */, 0xDAC143E5u /* xpaci x5 */, 0xDAC147E6u /* xpacd x6 */,
		                         0xD503415Fu /* msr dit, #1 */, 0xD51B42A4u /* msr dit, x4 */, 0xD50330FFu /* sb */ };
	for (unsigned i = 0; i < sizeof(nops) / sizeof(nops[0]); i++) {
		struct nopac_context before;
		c = fresh();
		before = c;
		RUN(nops[i]);
		before.pc += 4;
		assert(memcmp(&before, &c, sizeof(c)) == 0);
	}
	/* a PACIZA encoding with a modifier register is not an instruction */
	c = fresh();
	assert(nopac_emulate_instruction(0xDAC12044u, &c) == NOPAC_UNHANDLED);
	assert(nopac_emulate_instruction(0xD503201Fu /* nop */, &c) == NOPAC_UNHANDLED);
	assert(nopac_emulate_instruction(0xF9400041u /* ldr x1, [x2] */, &c) == NOPAC_UNHANDLED);

	/* PACGA: what the rewrite turns it into, eor x1, x2, x3, ror #13 */
	c = fresh();
	c.x[2] = 0x1234, c.x[3] = 0xFFFF0000FFFF2001ull;
	RUN(0x9AC33041u);
	assert(c.x[1] == (0x1234ull ^ (c.x[3] >> 13 | c.x[3] << 51)));
	c = fresh();
	RUN(0x9ADF3041u);       /* pacga x1, x2, sp: Rm 31 is the zero register of the EOR */
	assert(c.x[1] == c.x[2]);

	/* branches */
	c = fresh(); RUN(0xD71F0822u); assert(c.pc == 0x1001 && c.x[30] == 0x101E);          /* braa x1, x2 */
	c = fresh(); RUN(0xD61F0C7Fu); assert(c.pc == 0x1003);                               /* brabz x3 */
	c = fresh(); RUN(0xD73F0885u); assert(c.pc == 0x1004 && c.x[30] == 0x4004);          /* blraa x4, x5 */
	c = fresh(); RUN(0xD63F0CDFu); assert(c.pc == 0x1006 && c.x[30] == 0x4004);          /* blrabz x6 */
	c = fresh(); c.x[30] = 0x1000; RUN(0xD73F0BC0u | 0); assert(c.pc == 0x1000 && c.x[30] == 0x4004); /* blraa x30, x0 */
	c = fresh(); RUN(0xD65F0BFFu); assert(c.pc == 0x101E);                               /* retaa */
	c = fresh(); RUN(0xD65F0FFFu); assert(c.pc == 0x101E);                               /* retab */

	/* loads */
	c = fresh(); c.x[2] = memory_base;
	RUN(0xF8201441u);       /* ldraa x1, [x2, #8] */
	assert(c.x[1] == 0xAA01 && c.x[2] == memory_base && c.pc == 0x4004);
	c = fresh(); c.x[2] = memory_base + 4096 + 24;
	RUN(0xF8E00C41u);       /* ldrab x1, [x2, #-4096]! */
	assert(c.x[1] == 0xAA03 && c.x[2] == memory_base + 24);
	c = fresh(); c.sp = memory_base + 32 - 4088;
	RUN(0xF83FFFE1u);       /* ldraa x1, [sp, #4088]! */
	assert(c.x[1] == 0xAA04 && c.sp == memory_base + 32);
	c = fresh(); c.x[2] = 0x900000;
	assert(nopac_emulate_instruction(0xF8201441u, &c) == NOPAC_FAULT && c.pc == 0x4000 && c.x[1] == 0x1001);

	/* FJCVTZS against the C conversions */
	static const double exact[] = { 0.0, 1.0, -1.0, 2147483647.0, -2147483648.0, 123456.0 };
	for (unsigned i = 0; i < sizeof(exact) / sizeof(exact[0]); i++) {
		assert(fjcvtzs(exact[i], &flags) == (uint32_t)(int32_t)exact[i] && flags == 0x40000000u);
	}
	static const double inexact[] = { 0.5, -0.5, 1.75, -1.75, 2147483648.0, -2147483649.0, 4294967296.0, 4294967297.0,
		                          1e300, -1e300, 5e-324, 9007199254740993.0 };
	for (unsigned i = 0; i < sizeof(inexact) / sizeof(inexact[0]); i++) {
		double whole = trunc(inexact[i]), wrapped = fmod(whole, 4294967296.0);
		if (wrapped < 0) {
			wrapped += 4294967296.0;
		}
		assert(fjcvtzs(inexact[i], &flags) == (uint32_t)wrapped && flags == 0);
	}
	assert(fjcvtzs(NAN, &flags) == 0 && flags == 0);
	assert(fjcvtzs(INFINITY, &flags) == 0 && flags == 0);
	assert(fjcvtzs(-0.0, &flags) == 0 && flags == 0);
	c = fresh(); c.has_fp = false;
	assert(nopac_emulate_instruction(0x1E7E0041u, &c) == NOPAC_UNHANDLED);

	/* flags */
	c = fresh(); c.nzcv = 0x20000000u; RUN(0xD500401Fu); assert(c.nzcv == 0);                       /* cfinv */
	c = fresh(); c.x[1] = 0xA << 5; c.nzcv = 0xF0000000u; RUN(0xBA02842Au);                         /* rmif x1, #5, #10 */
	assert(c.nzcv == ((0xF0000000u & ~0xA0000000u) | 0xA0000000u));
	c = fresh(); c.x[1] = 0; c.nzcv = 0xF0000000u; RUN(0xBA02842Au); assert(c.nzcv == 0x50000000u);
	c = fresh(); c.x[3] = 0x80; c.nzcv = 0x20000000u; RUN(0x3A00086Du);                             /* setf8 w3 */
	assert(c.nzcv == (0x80000000u | 0x20000000u | 0x10000000u));
	c = fresh(); c.x[3] = 0x100; c.nzcv = 0; RUN(0x3A00086Du); assert(c.nzcv == (0x40000000u | 0x10000000u));
	c = fresh(); c.x[4] = 0x18000; c.nzcv = 0; RUN(0x3A00488Du); assert(c.nzcv == 0x80000000u);     /* setf16 w4 */
	c = fresh(); c.nzcv = 0x30000000u; RUN(0xD500405Fu); assert(c.nzcv == 0x40000000u);             /* axflag */
	c = fresh(); c.nzcv = 0x20000000u; RUN(0xD500405Fu); assert(c.nzcv == 0x20000000u);
	c = fresh(); c.nzcv = 0x40000000u; RUN(0xD500403Fu); assert(c.nzcv == 0x30000000u);             /* xaflag */
	c = fresh(); c.nzcv = 0; RUN(0xD500403Fu); assert(c.nzcv == 0x80000000u);
	c = fresh(); c.x[3] = 5; RUN(0xD53B42A3u); assert(c.x[3] == 0);                                 /* mrs x3, dit */

	puts("ok");
	return 0;
}

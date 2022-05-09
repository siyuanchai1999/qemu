// SPDX-License-Identifier: GPL-2.0
#include <inttypes.h>
#include <stdio.h>

#define NUM_CRC64_TABLE 4

/* source of the polynomials: https://en.wikipedia.org/wiki/Cyclic_redundancy_check */
#define CRC64_ECMA182_POLY_0 0x42F0E1EBA9EA3693ULL
#define CRC64_ECMA182_POLY_1 0xC96C5795D7870F42ULL
#define CRC64_ECMA182_POLY_2 0x92D8AF2BAF0E1E85ULL
#define CRC64_ECMA182_POLY_3 0xA17870F5D4F51B49ULL

static uint64_t polynomials[NUM_CRC64_TABLE] = {
	CRC64_ECMA182_POLY_0,
	CRC64_ECMA182_POLY_1,
	CRC64_ECMA182_POLY_2,
	CRC64_ECMA182_POLY_3
};

static uint64_t crc64_table[NUM_CRC64_TABLE][256] = {0};

static void generate_crc64_table(uint64_t poly, int n_table)
{
	uint64_t i, j, c, crc;

	for (i = 0; i < 256; i++) {
		crc = 0;
		c = i << 56;

		for (j = 0; j < 8; j++) {
			if ((crc ^ c) & 0x8000000000000000ULL)
				crc = (crc << 1) ^ poly;
			else
				crc <<= 1;
			c <<= 1;
		}

		crc64_table[n_table][i] = crc;
	}
}

static void print_crc64_table(char * h_filename)
{
	int i, t;
	FILE * fp = fopen(h_filename, "w+");

	if (fp) {

		fprintf(fp, "/* this file is generated - do not edit */\n\n");
		// printf("#include <linux/types.h>\n");
		fprintf(fp, "#include \"qemu/osdep.h\"\n");
		fprintf(fp, "static const uint64_t ecpt_crc64table[%d][256] = {\n", NUM_CRC64_TABLE);
		for (t = 0; t < NUM_CRC64_TABLE; t++) {
			fprintf(fp, "{");
			for (i = 0; i < 256; i++) {
				fprintf(fp, "\t0x%016" PRIx64 "ULL", crc64_table[t][i]);
				if (i & 0x1)
					fprintf(fp, ",\n");
				else
					fprintf(fp, ", ");
			}
			fprintf(fp, "},\n");
		}
		fprintf(fp, "};\n");

		fclose(fp);
	}
}

int main(int argc, char *argv[])
{
	int i;
	for (i = 0; i < NUM_CRC64_TABLE; i++) {
		generate_crc64_table(polynomials[i], i);
	}
	if (argc >= 2) {
		print_crc64_table(argv[1]);
	}
	
	return 0;
}
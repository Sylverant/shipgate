/*
    Sylverant Ship Key Generator
    Copyright (C) 2009 Lawrence Sebald

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 3 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>

#include <sylverant/config.h>
#include <sylverant/database.h>
#include <sylverant/sha4.h>

#define RNG_SIZE 1048576
#define HALF_SIZE (RNG_SIZE / 2)

#if defined(WORDS_BIGENDIAN) || defined(__BIG_ENDIAN__)
#define LE32(x) (((x >> 24) & 0x00FF) | \
                 ((x >>  8) & 0xFF00) | \
                 ((x & 0xFF00) <<  8) | \
                 ((x & 0x00FF) << 24))
#else
#define LE32(x) x
#endif

/* Enough space for 1MB of random data to generate our key from. */
unsigned char rndbuf[RNG_SIZE];

int main(int argc, char *argv[]) {
    sylverant_dbconfig_t cfg;
    sylverant_dbconn_t conn;
    char query[1024], data[512];
    FILE *fp, *r;
    unsigned char key[128];
    int i;
    uint32_t index;

    /* Generate the random data used to create our key. */
    if((r = fopen("/dev/random", "rb")) == NULL) {
        fprintf(stderr, "Couldn't open /dev/random!\n");
        exit(EXIT_FAILURE);
    }

    /* Generate 1MB of random numbers to hash to create the key. */
    fread(rndbuf, RNG_SIZE, 1, r);
    fclose(r);

    /* Connect to the database. */
    if(sylverant_read_dbconfig(&cfg)) {
        fprintf(stderr, "Couldn't read database configuration!\n");
        exit(EXIT_FAILURE);
    }

    if((fp = fopen("ship_key.bin", "wb")) == NULL) {
        fprintf(stderr, "Couldn't open key file for writing!\n");
        exit(EXIT_FAILURE);
    }

    if(sylverant_db_open(&cfg, &conn)) {
        fprintf(stderr, "Couldn't connect to the database!\n");
        fclose(fp);
        unlink("ship_key.bin");
        exit(EXIT_FAILURE);
    }

    /* Hash the generated random data to get our real key. */
    sha4(rndbuf, HALF_SIZE, key, 0);
    sha4(rndbuf + HALF_SIZE, HALF_SIZE, key + 64, 0);

    /* Prepare the database query. */
    sylverant_db_escape_str(&conn, data, (char *)key, 128);
    sprintf(query, "INSERT INTO ship_data(rc4key) VALUES('%s')", data);

    if(sylverant_db_query(&conn, query)) {
        fprintf(stderr, "Couldn't query the database!\n");
        fclose(fp);
        unlink("ship_key.bin");
        exit(EXIT_FAILURE);
    }

    /* Grab the key index. */
    index = (uint32_t)sylverant_db_insert_id(&conn);
    index = LE32(index);

    /* Write the key to the file. */
    fwrite(&index, 1, 4, fp);
    fwrite(key, 1, 128, fp);
    fclose(fp);
    
    exit(EXIT_SUCCESS);
}

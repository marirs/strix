/*
 * Minimal test program for strix format fixtures.
 *
 * Embeds known strings into the binary so integration tests can assert
 * that the static-string extractor finds them, with correct section
 * labeling and the right executable/data flags.
 *
 * The two STRIX_ markers are unique enough not to clash with the
 * compiler's own runtime strings.
 */

#include <stdio.h>

const char *STRIX_FIXTURE_RDATA  = "STRIX_FIXTURE_RDATA_HELLO";
const char *STRIX_FIXTURE_RDATA2 = "STRIX_FIXTURE_RDATA_WORLD";

int main(void) {
    printf("STRIX_FIXTURE_MAIN: %s %s\n",
           STRIX_FIXTURE_RDATA,
           STRIX_FIXTURE_RDATA2);
    return 0;
}

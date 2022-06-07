/* main.h
 *
 * Copyright (C) 2022 shahrukh hussain <shahrukh@discreteworks.com>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include "suci_define.h"
#include "suci_test_keys.h"

// Dynamic linking requires
//export LD_LIBRARY_PATH="${LD_LIBRARY_PATH}:/usr/local/lib"

int main () {
    byte profile_a_output[256] = { 0 };
    byte profile_b_output[256] = { 0 };
    int ret;
    
    ret = profile_a(supi_a, sizeof(supi_a), pub_key_buf_a, eph_pri_key_buf_a, eph_pub_key_buf_a, profile_a_output);
    
    printf("profile a ret: %d\n", ret);

    if (0 == memcmp(profile_a_output, scheme_output_a, sizeof(scheme_output_a))) {
        printf("profile a encoded correctly.\n");
    }

    ret = profile_b(supi_b, sizeof(supi_b), pub_key_buf_comp_b, sizeof(pub_key_buf_comp_b), eph_pri_key_buf_comp_b, sizeof(eph_pri_key_buf_comp_b),  eph_pub_key_buf_comp_b, sizeof(eph_pub_key_buf_comp_b), profile_b_output);

    printf("profile b ret: %d\n", ret);

    if (0 == memcmp(profile_b_output, scheme_output_b, sizeof(scheme_output_b))) {
        printf("profile b encoded correctly.\n");
    }

    return 0;
}

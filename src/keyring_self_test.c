/* SPDX-License-Identifier: Apache-2.0 */
/*
 * OpenSSL Keyring Provider - Self-Test
 */


#include <keyutils.h>
#include "keyring_provider.h"

/* Self-test: Check kernel keyring capabilities */
int keyring_self_test(void)
{
    unsigned char caps[256];
    long ret;
    int have_public_key = 0;

    /* Call keyctl_capabilities to get capability bits */
    ret = keyctl_capabilities(caps, sizeof(caps));
    if (ret < 0) {
        keyring_error(0, KEYRING_ERR_OPERATION,
                     "keyctl_capabilities failed: %ld", ret);
        return 0;
    }

    /* Decode CAPS0 (first byte) capabilities */
    if (ret > 0) {
        unsigned char caps0 = caps[0];

        keyring_info("have_capabilities=%d", (caps0 & KEYCTL_CAPS0_CAPABILITIES) ? 1 : 0);
        keyring_info("have_persistent_keyrings=%d", (caps0 & KEYCTL_CAPS0_PERSISTENT_KEYRINGS) ? 1 : 0);
        keyring_info("have_dh_compute=%d", (caps0 & KEYCTL_CAPS0_DIFFIE_HELLMAN) ? 1 : 0);
        keyring_info("have_public_key=%d", (caps0 & KEYCTL_CAPS0_PUBLIC_KEY) ? 1 : 0);
        keyring_info("have_big_key_type=%d", (caps0 & KEYCTL_CAPS0_BIG_KEY) ? 1 : 0);
        keyring_info("have_key_invalidate=%d", (caps0 & KEYCTL_CAPS0_INVALIDATE) ? 1 : 0);
        keyring_info("have_restrict_keyring=%d", (caps0 & KEYCTL_CAPS0_RESTRICT_KEYRING) ? 1 : 0);
        keyring_info("have_move_key=%d", (caps0 & KEYCTL_CAPS0_MOVE) ? 1 : 0);

        have_public_key = (caps0 & KEYCTL_CAPS0_PUBLIC_KEY) ? 1 : 0;
    }

    /* Decode CAPS1 (second byte) capabilities */
    if (ret > 1) {
        unsigned char caps1 = caps[1];

        keyring_info("have_ns_keyring_name=%d", (caps1 & KEYCTL_CAPS1_NS_KEYRING_NAME) ? 1 : 0);
        keyring_info("have_ns_key_tag=%d", (caps1 & KEYCTL_CAPS1_NS_KEY_TAG) ? 1 : 0);
        keyring_info("have_notify=%d", (caps1 & KEYCTL_CAPS1_NOTIFICATIONS) ? 1 : 0);
    }

    /* Check if PUBLIC_KEY capability is present - required for this provider */
    if (!have_public_key) {
        keyring_error(0, KEYRING_ERR_OPERATION,
                     "Kernel keyring does not support public key operations (KEYCTL_CAPS0_PUBLIC_KEY missing)");
        return 0;
    }

    return 1;
}

package org.haox.kerb.client.preauth;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;

public class PreauthContext {

    /**
     * Get the client-supplied reply key, possibly derived from password
     */
    public EncryptionKey getAsKey() throws KrbException {
        return null;
    }

    /**
     * Replace the reply key to be used to decrypt the AS response.
     */
    public void setAsKey(EncryptionKey asKey) {

    }

    /**
     * Get the enctype expected to be used to encrypt the encrypted portion of
     * the AS_REP packet.  When handling a PREAUTH_REQUIRED error, this
     * typically comes from etype-info2.  When handling an AS reply, it is
     * initialized from the AS reply itself.
     */
    public EncryptionType getEncType() {
        return null;
    }

    /**
     * Get a pointer to the FAST armor key, or NULL if the client is not using FAST.
     */
    public EncryptionKey getArmorKey() {
        return null;
    }

    /**
     * Get the current time for use in a preauth response.  If
     * allow_unauth_time is true and the library has been configured to allow
     * it, the current time will be offset using unauthenticated timestamp
     * information received from the KDC in the preauth-required error, if one
     * has been received.  Otherwise, the timestamp in a preauth-required error
     * will only be used if it is protected by a FAST channel.  Only set
     * allow_unauth_time if using an unauthenticated time offset would not
     * create a security issue.
     */
    public KerberosTime getPreauthTime() {
        return KerberosTime.now();
    }
}
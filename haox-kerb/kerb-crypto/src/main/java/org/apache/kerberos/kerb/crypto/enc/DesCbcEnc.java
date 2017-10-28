package org.apache.kerberos.kerb.crypto.enc;

import org.apache.kerberos.kerb.KrbErrorCode;
import org.apache.kerberos.kerb.crypto.Confounder;
import org.apache.kerberos.kerb.crypto.cksum.HashProvider;
import org.apache.kerberos.kerb.crypto.enc.provider.DesProvider;
import org.apache.kerberos.kerb.crypto.key.DesKeyMaker;
import org.apache.kerberos.kerb.KrbException;

abstract class DesCbcEnc extends AbstractEncTypeHandler {

    public DesCbcEnc(HashProvider hashProvider) {
        super(new DesProvider(), hashProvider);
        keyMaker(new DesKeyMaker(this.encProvider()));
    }

    //Fixing https://issues.apache.org/jira/projects/DIRKRB/issues/DIRKRB-472?
    // error in Java implementation of haox
    @Override
    protected void encryptWith(byte[] workBuffer, int[] workLens,
                                 byte[] key, byte[] iv, int usage) throws KrbException {
        int confounderLen = workLens[0];
        int checksumLen = workLens[1];
        int dataLen = workLens[2];
        int paddingLen = workLens[3];

        // confounder
        byte[] confounder = Confounder.makeBytes(confounderLen);
        System.arraycopy(confounder, 0, workBuffer, 0, confounderLen);

        // padding
        for (int i = confounderLen + checksumLen + dataLen; i < paddingLen; ++i) {
            workBuffer[i] = 0; // Empty the workbuffer here
        }

        byte[] checksum = new byte[checksumLen];
        for (int i = 0; i < checksumLen; i++) {
            checksum[i] = workBuffer[confounderLen + i];
            workBuffer[confounderLen + i] = 0;
        }

        // checksum
        hashProvider().hash(workBuffer);
        byte[] cksum = hashProvider().output();
        System.arraycopy(cksum, 0, workBuffer, confounderLen, checksumLen);

        //The idea is that doublt check at the time of encryption too
        //to figure out if checksum are equal.
        // that way if we don't encrypt faulty keys then decryption won't
        // result in error too.
        if (! checksumEqual(checksum, cksum)) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BAD_INTEGRITY);
        }
        encProvider().encrypt(key, iv, workBuffer);
    }

    @Override
    protected byte[] decryptWith(byte[] workBuffer, int[] workLens,
                                 byte[] key, byte[] iv, int usage) throws KrbException {
        int confounderLen = workLens[0];
        int checksumLen = workLens[1];
        int dataLen = workLens[2];

        encProvider().decrypt(key, iv, workBuffer);

        byte[] checksum = new byte[checksumLen];
        for (int i = 0; i < checksumLen; i++) {
            checksum[i] = workBuffer[confounderLen + i];
            workBuffer[confounderLen + i] = 0;
        }

        hashProvider().hash(workBuffer);
        byte[] newChecksum = hashProvider().output();
        if (! checksumEqual(checksum, newChecksum)) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BAD_INTEGRITY);
        }

        byte[] data = new byte[dataLen];
        System.arraycopy(workBuffer, confounderLen + checksumLen,
                data, 0, dataLen);

        return data;
    }
}

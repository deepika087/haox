package org.apache.haox.asn1;

import org.apache.haox.asn1.type.Asn1ObjectIdentifier;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;

public class TestAsn1ObjectIdentifier {

    @Test
    public void testEncoding() throws Exception {
        /**
         * Cryptography for Developers -> ASN.1 UTCTIME Type
         * Applying this to the MD5 OID, we ﬁrst transform the dotted decimal form into the
         * array of words.Thus, 1.2.840.113549.2.5 becomes {42, 840, 113549, 2, 5}, and then further
         * 404_CRYPTO_02.qxd 10/27/06 3:40 PM Page 36split into seven-bit digits with the proper most signiﬁcant bits as
         * {{0x2A}, {0x86, 0x48},{0x86, 0xF7, 0x0D}, {0x02}, {0x05}}.Therefore, the full encoding for MD5 is 0x06 08 2A
         * 86 48 86 F7 0D 02 05.
         */
        testEncodingWith("1.2.840.113549.2.5",
                "0x06 08 2A 86 48 86 F7 0D 02 05");
    }

    private void testEncodingWith(String oid, String expectedEncoding) {
        byte[] expected = Util.hex2bytes(expectedEncoding);
        Asn1ObjectIdentifier aValue = new Asn1ObjectIdentifier(oid);
        aValue.setEncodingOption(EncodingOption.DER);
        byte[] encodingBytes = aValue.encode();
        Assert.assertArrayEquals(expected, encodingBytes);
    }

    @Test
    public void testDecoding() throws Exception {
        testDecodingWith("1.2.840.113549.2.5",
                "0x06 08 2A 86 48 86 F7 0D 02 05");
    }

    private void testDecodingWith(String expectedValue, String content) throws IOException {
        Asn1ObjectIdentifier decoded = new Asn1ObjectIdentifier();
        decoded.setEncodingOption(EncodingOption.DER);
        decoded.decode(Util.hex2bytes(content));
        Assert.assertEquals(expectedValue, decoded.getValue());
    }
}

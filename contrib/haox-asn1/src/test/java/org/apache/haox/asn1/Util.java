package org.apache.haox.asn1;

public class Util {

    final static String HEX_CHARS_STR = "0123456789ABCDEF";
    final static char[] HEX_CHARS = HEX_CHARS_STR.toCharArray();

    /**
     * Convert bytes into format as:
     * 0x02 02 00 80
     */
    public static String bytesToHex(byte[] bytes) {
        int len = bytes.length * 2;
        len += bytes.length; // for ' ' appended for each char
        len += 2; // for '0x' prefix
        char[] hexChars = new char[len];
        hexChars[0] = '0';
        hexChars[1] = 'x';
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 3 + 2] = HEX_CHARS[v >>> 4];
            hexChars[j * 3 + 3] = HEX_CHARS[v & 0x0F];
            hexChars[j * 3 + 4] = ' ';
        }

        return new String(hexChars);
    }

    /**
     * Convert hex string like follows into byte array
     * 0x02 02 00 80
     */
    public static byte[] hex2bytes(String hexString) {
        hexString = hexString.toUpperCase();
        String hexStr = hexString;
        if (hexString.startsWith("0X")) {
            hexStr = hexString.substring(2);
        }
        String[] hexParts = hexStr.split(" ");

        byte[] bytes = new byte[hexParts.length];
        char[] hexPart;
        for (int i = 0; i < hexParts.length; ++i) {
            hexPart = hexParts[i].toCharArray();
            if (hexPart.length != 2) {
                throw new IllegalArgumentException("Invalid hex string to convert");
            }
            bytes[i] = (byte) ((HEX_CHARS_STR.indexOf(hexPart[0]) << 4) + HEX_CHARS_STR.indexOf(hexPart[1]));
        }

        return bytes;
    }
}
package com.presseverykey.u2f;

/**
 * Created by a2800276 on 2015-10-29.
 */
public class APDU {
    static final byte CLA = 0;
    static final byte INS = 1;
    static final byte P1 = 2;
    static final byte P2 = 3;
    static final byte LC1 = 4; //MSB
    static final byte LC2 = 5;
    static final byte LC3 = 6; //LSB

    byte cla;
    byte ins;
    byte p1;
    byte p2;
    byte lc1; //MSB
    byte lc2;
    byte lc3; //LSB
    int length;
    byte[] payload;

    public byte[] toBytes() {
        length = payload == null ? 0 : payload.length;
        byte[] apdu = new byte[length + 7];
        lc1 = (byte) (length >> 16);
        lc2 = (byte) ((length >> 8) & 0xff);
        lc3 = (byte) (length & 0xff);


        apdu[CLA] = cla;
        apdu[INS] = ins;
        apdu[P1] = p1;
        apdu[P2] = p2;
        apdu[LC1] = lc1;
        apdu[LC2] = lc2;
        apdu[LC3] = lc3;

        if (payload != null) {
            System.arraycopy(payload, 0, apdu, 7, payload.length);
        }
        return apdu;
    }

    public static APDU scan(byte[] bytes) throws APDUException {
        if (bytes.length < 7) {
            throw new APDUException("not enough data");
        }
        APDU apdu = new APDU();
        apdu.cla = bytes[CLA];
        apdu.ins = bytes[INS];
        apdu.p1 = bytes[P1];
        apdu.p2 = bytes[P2];
        apdu.lc1 = bytes[LC1];
        apdu.lc2 = bytes[LC2];
        apdu.lc3 = bytes[LC3];

        apdu.length |= apdu.lc1;
        apdu.length <<= 8;
        apdu.length |= apdu.lc2;
        apdu.length <<= 8;
        apdu.length |= apdu.lc3;

        if (bytes.length != 7 + apdu.length) {
            throw new APDUException("incorrect request-data length");
        }

        apdu.payload = new byte[apdu.length];
        System.arraycopy(bytes, 7, apdu.payload, 0, apdu.length);

        return apdu;
    }

    static class APDUException extends RuntimeException {
        public APDUException(String mes) {
            super(mes);
        }
    }

    static void p(Object o) {
        System.out.println(o);
    }
}

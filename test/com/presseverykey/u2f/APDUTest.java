package com.presseverykey.u2f;

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Created by a2800276 on 2015-10-29.
 */
public class APDUTest {
    static final byte[] three_byte_payload = {0x01, 0x02, 0x03};

    @org.testng.annotations.Test
    public void testToBytes() throws Exception {
        APDU apdu = new APDU();
        apdu.cla = 0x00;
        apdu.ins = 0x01;
        apdu.p1 = 0x02;
        apdu.p2 = 0x03;
        byte[] bytes = apdu.toBytes();
        assertEquals(bytes.length, 7);
        assertEquals(apdu.lc1, 0);
        assertEquals(apdu.lc2, 0);
        assertEquals(apdu.lc3, 0);

        apdu.payload = three_byte_payload;
        bytes = apdu.toBytes();
        assertEquals(bytes.length, 10);
        assertEquals(bytes[7], 1);
        assertEquals(bytes[8], 2);
        assertEquals(bytes[9], 3);
        assertEquals(apdu.lc1, 0);
        assertEquals(apdu.lc2, 0);
        assertEquals(apdu.lc3, 3);


        apdu.payload = new byte[0x100];
        bytes = apdu.toBytes();
        assertEquals(bytes.length, 0x107);
        assertEquals(apdu.lc1, 0);
        assertEquals(apdu.lc2, 1);
        assertEquals(apdu.lc3, 0x00);

        apdu.payload = new byte[0x10203];
        bytes = apdu.toBytes();
        assertEquals(bytes.length, 0x1020A);
        assertEquals(apdu.lc1, 1);
        assertEquals(apdu.lc2, 0x02);
        assertEquals(apdu.lc3, 0x03);

        assertEquals(apdu.cla, 0);
        assertEquals(apdu.ins, 1);
        assertEquals(apdu.p1, 2);
        assertEquals(apdu.p2, 3);
    }

    static final byte[] malformed_apdu = {0x01, 0x02, 0x03};

    @Test(expectedExceptions = APDU.APDUException.class)
    public void testScanMalformed() throws Exception {
        APDU.scan(malformed_apdu);
    }

    static final byte[] malformed_apdu2 = {0x01, 0x02, 0x03, 0x04, 0x7f, 0x00, 0x00, 0x01};

    @Test(expectedExceptions = APDU.APDUException.class)
    public void testScanMalformed2() throws Exception {
        APDU.scan(malformed_apdu2);
    }

    static final byte[] malformed_apdu3 = {0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x01};

    @Test(expectedExceptions = APDU.APDUException.class)
    public void testScanMalformed3() throws Exception {
        APDU.scan(malformed_apdu3);
    }

    static final byte[] empty_payload = {0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00};
    static final byte[] nonempty_payload = {0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x01, 0x05};

    @Test
    public void testScanSuccess() throws Exception {
        APDU a = APDU.scan(empty_payload);
        assertEquals(a.cla, 1);
        assertEquals(a.ins, 2);
        assertEquals(a.p1, 3);
        assertEquals(a.p2, 4);
        assertEquals(a.lc1, 0);
        assertEquals(a.lc2, 0);
        assertEquals(a.lc3, 0);
        assertEquals(a.length, 0);
        assertEquals(a.payload.length, 0);

        a = APDU.scan(nonempty_payload);
        assertEquals(a.cla, 1);
        assertEquals(a.ins, 2);
        assertEquals(a.p1, 3);
        assertEquals(a.p2, 4);
        assertEquals(a.lc1, 0);
        assertEquals(a.lc2, 0);
        assertEquals(a.lc3, 1);
        assertEquals(a.length, 1);
        assertEquals(a.payload[0], 5);

        byte[] long_apdu = new byte[0x10007];
        long_apdu[APDU.LC1] = 1;
        long_apdu[7] = 7;

        a = APDU.scan(long_apdu);
        assertEquals(a.cla, 0);
        assertEquals(a.ins, 0);
        assertEquals(a.p1, 0);
        assertEquals(a.p2, 0);
        assertEquals(a.lc1, 1);
        assertEquals(a.lc2, 0);
        assertEquals(a.lc3, 0);
        assertEquals(a.length, 0x10000);
        assertEquals(a.payload[0], 7);
    }

}
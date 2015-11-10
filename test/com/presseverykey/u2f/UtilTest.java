package com.presseverykey.u2f;

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Created by a2800276 on 2015-10-29.
 */
public class UtilTest {

    byte[] bytes = {0x01, 0x02, 0x31, 0x32, (byte) 0xff};

    @Test
    public void testBytesToHex() throws Exception {
        assertEquals(Util.bytes2Hex(bytes, 0, bytes.length), "01023132FF");
    }
}
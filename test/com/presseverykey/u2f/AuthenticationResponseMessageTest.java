package com.presseverykey.u2f;

import org.testng.annotations.Test;

import static de.kuriositaet.util.crypto.Random.random;
import static org.testng.Assert.assertEquals;

/**
 * Created by a2800276 on 2015-11-18.
 */
public class AuthenticationResponseMessageTest {
    static byte[] ONE2FOUR = {1, 2, 3, 4};
    static byte[] SIGNATURE = random(32);

    @Test
    public void testToBytes() throws Exception {
        U2F.AuthenticationResponseMessage resp = new U2F.AuthenticationResponseMessage();
        resp.counter = ONE2FOUR;
        resp.signature = SIGNATURE;
        byte[] respBytes = resp.toBytes();

        assertEquals(respBytes.length, ONE2FOUR.length + SIGNATURE.length + 1);

        byte[] respCounter = new byte[4];
        byte[] respSignature = new byte[SIGNATURE.length];

        System.arraycopy(respBytes, 1, respCounter, 0, 4);
        System.arraycopy(respBytes, 5, respSignature, 0, respBytes.length - 5);

        assertEquals(respCounter, ONE2FOUR);
        assertEquals(respSignature, SIGNATURE);

    }
}
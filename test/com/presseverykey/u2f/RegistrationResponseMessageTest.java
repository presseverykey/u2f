package com.presseverykey.u2f;

import org.testng.annotations.Test;

import static de.kuriositaet.util.crypto.Random.random;
import static org.testng.Assert.assertEquals;

/**
 * Created by a2800276 on 2015-11-10.
 */
public class RegistrationResponseMessageTest {

    @Test
    public void testToBytes() throws Exception {
        U2F.RegistrationResponseMessage resp = new U2F.RegistrationResponseMessage();
        byte[] pk = random(65);
        resp.setUserPK(pk);
        resp.setAttestationCert(random(64));
        resp.setKeyHandle(random(64));
        resp.setSignature(random(64));
        byte[] bytes = resp.toBytes();
        assertEquals(bytes[0], 0x05);
        for (int i = 0; i != 65; ++i) {
            assertEquals(bytes[i + 1], pk[i]);
        }
    }
}
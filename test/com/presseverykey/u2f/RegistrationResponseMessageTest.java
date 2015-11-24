package com.presseverykey.u2f;

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static util.crypto.Random.random;

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

	@Test
	void testInvalidValues() throws Exception {
		U2F.RegistrationResponseMessage resp = new U2F.RegistrationResponseMessage();
		byte[][] invalidPKs = new byte[5][];

		invalidPKs[0] = random(66);
		invalidPKs[1] = random(64);
		invalidPKs[2] = random(0);
		invalidPKs[3] = random(1);
		invalidPKs[4] = null;

		for (byte[] pk : invalidPKs) {
			try {
				resp.setUserPK(pk);
				assertTrue(false);
			} catch (U2F.U2FException u2fe) {

			}
		}

		byte[][] invalidKeyHandles = new byte[4][];

		invalidKeyHandles[0] = null;
		invalidKeyHandles[1] = random(0);
		invalidKeyHandles[1] = random(1);
		invalidKeyHandles[1] = random(256);

		for (byte[] kh : invalidKeyHandles) {
			try {
				resp.setKeyHandle(kh);
				assertTrue(false);
			} catch (U2F.U2FException u2fe) {
			}
		}
	}
}
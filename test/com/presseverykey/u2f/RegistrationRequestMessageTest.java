package com.presseverykey.u2f;

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * Created by a2800276 on 2015-11-10.
 */
public class RegistrationRequestMessageTest {
    static final byte[] ONES = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    static final byte[] ZEROS = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    static final byte[] ZEROS_AND_ONES = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

    @Test
    public void testConstructor() {
        U2F.RegistrationRequestMessage req = new U2F.RegistrationRequestMessage(ZEROS_AND_ONES);
        assertEquals(req.getChallengeParameter(), ZEROS);
        assertEquals(req.getApplicationParameter(), ONES);
        boolean thrown = false;
        try {
            req = new U2F.RegistrationRequestMessage(ZEROS);
        } catch (Throwable t) {
            thrown = true;
            assertEquals(t.getClass(), U2F.U2FException.class);
        }
        assertTrue(thrown);
        thrown = false;
        try {
            req = new U2F.RegistrationRequestMessage(null);
        } catch (Throwable t) {
            thrown = true;
            assertEquals(t.getClass(), U2F.U2FException.class);
        }
    }

}
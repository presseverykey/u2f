package com.presseverykey.u2f;

import org.testng.annotations.Test;

import java.io.Closeable;
import java.io.IOException;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * Created by a2800276 on 2015-10-29.
 */
public class UtilTest {


    @Test
    public void testCloseStream() throws Exception {
        class Wrap {
            boolean called;
        }
        final Wrap w = new Wrap();

        Closeable close = new Closeable() {
            @Override
            public void close() throws IOException {
                if (!w.called) {
                    w.called = true;
                    throw new IOException("waaaaaaah!");
                } else {
                    throw new U2F.U2FException();
                }
            }
        };
        // first time throw an IOException, that should be ignored.
        Util.close(close);
        assertTrue(w.called);
        boolean thrown = false;
        try {
            // second time throw something else, that ought to be passed on.
            Util.close(close);
        } catch (Throwable t) {
            assertEquals(t.getClass(), U2F.U2FException.class);
            thrown = true;
        }
        assertTrue(thrown);
        Util.close(null);
    }

}
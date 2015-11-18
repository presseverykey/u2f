package com.presseverykey.u2f;

import java.io.Closeable;
import java.io.IOException;

/**
 * Created by a2800276 on 2015-10-29.
 */
public class Util {

    public static void close(Closeable stream) {
        if (null != stream) {
            try {
                stream.close();
            } catch (IOException ioe) {
                // ignore.
            }
        }
    }


    public static void p(Object o) {
        System.out.println(o);
    }

    public static void p(Object[] os) {
        for (Object o : os) {
            p(o);
        }
    }
}

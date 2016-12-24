package com.yakivmospan.scytale;

import android.os.Build;

final class Utils {
    static final int VERSION = Build.VERSION.SDK_INT;
    static String TAG = Options.class.getName();

    private Utils() {
    }

    /**
     * @return true it current api version is lower then 18
     */
    static boolean lowerThenJellyBean() {
        return VERSION < Build.VERSION_CODES.JELLY_BEAN_MR2;
    }

    /**
     * @return true it current api version is lower then 23
     */
    static boolean lowerThenMarshmallow() {
        return VERSION < Build.VERSION_CODES.M;
    }

    /**
     * @return true it current api version is bigger then 18
     */
    static boolean biggerThenJellyBean() {
        return VERSION > Build.VERSION_CODES.JELLY_BEAN_MR2;
    }

    /**
     * @return true it current api version is 18
     */
    static boolean isJellyBean() {
        return VERSION == Build.VERSION_CODES.JELLY_BEAN_MR2;
    }
}

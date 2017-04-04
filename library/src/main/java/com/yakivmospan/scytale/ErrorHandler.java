package com.yakivmospan.scytale;

import android.util.Log;

class ErrorHandler {
    private ErrorListener mErrorListener;

    /**
     * Use this method to handle errors that may occur while working with this class. Error log with short information
     * about exception will be printed to log cat even if there is no {@link ErrorListener} specified.
     *
     * @param errorListener will be triggered if any error occurs.
     */
    public void setErrorListener(ErrorListener errorListener) {
        mErrorListener = errorListener;
    }

    /**
     * Prints exception in logs and triggers listener if it is not null
     */
    protected void onException(Exception e) {
        if (BuildConfig.DEBUG) {
            Log.e(Utils.TAG, Log.getStackTraceString(e));
        } else {
            Log.e(Utils.TAG, e.toString());
        }
        if (mErrorListener != null) {
            mErrorListener.onError(e);
        }
    }
}

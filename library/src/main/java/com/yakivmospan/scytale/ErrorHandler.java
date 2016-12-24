package com.yakivmospan.scytale;

import android.util.Log;

class ErrorHandler {
    private ErrorListener mErrorListener;

    public void setErrorListener(ErrorListener errorListener) {
        mErrorListener = errorListener;
    }

    /**
     * Prints exception in logs and triggers listener if it is not null
     */
    protected void onException(Exception e) {
        if (BuildConfig.DEBUG) {
            e.printStackTrace();
        } else {
            Log.e(Utils.TAG, e.getMessage());
            Log.e(Utils.TAG, e.toString());
        }
        if (mErrorListener != null) {
            mErrorListener.onError(e);
        }
    }
}

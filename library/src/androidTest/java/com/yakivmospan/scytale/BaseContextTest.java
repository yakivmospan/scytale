package com.yakivmospan.scytale;

import org.junit.Before;

import android.content.Context;
import android.support.test.InstrumentationRegistry;

public class BaseContextTest {

    protected Context context;

    @Before
    public void setup() {
        context = InstrumentationRegistry.getTargetContext();
    }

}

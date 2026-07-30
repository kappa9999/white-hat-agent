package org.whitehat.fixture;

public final class MinimalAndroid {
    private MinimalAndroid() {}

    public static String marker() {
        return "WHA_ANDROID_FIXTURE";
    }

    public static int add(int left, int right) {
        return left + right;
    }

    public static int markerLength() {
        return marker().length();
    }
}

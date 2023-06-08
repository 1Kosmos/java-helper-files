package com.bidsdk.utils;

import java.util.List;

public class ArrayHelper {
    public static boolean containString(List<String> array, String target) {
        for (String element : array) {
            if (element.equals(target)) {
                return true;
            }
        }
        return false;
    }
}

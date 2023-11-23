package com.bidsdk;

import java.security.MessageDigest;

public class UtilityClass {

    public static String get_SHA_512(String base, String salt) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            if (UtilityClass.isValidString(salt)) {
                digest.update(salt.getBytes());
            }
            byte[] hash = digest.digest(base.getBytes("UTF-8"));
            StringBuffer hexString = new StringBuffer();

            for (int i = 0; i < hash.length; i++) {
                String hex = Integer.toHexString(0xff & hash[i]);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }

            return hexString.toString();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
    
    public static boolean isValidString(String str) {
        return (str != null && !str.isEmpty()) ? true : false;
    }
}

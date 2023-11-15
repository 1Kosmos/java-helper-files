/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */
package com.bidsdk;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.binary.Base32;
import org.apache.http.HttpStatus;

import com.bidsdk.model.BIDCommunityInfo;
import com.bidsdk.model.BIDKeyPair;
import com.bidsdk.model.BIDOtpResponse;
import com.bidsdk.model.BIDOtpValue;
import com.bidsdk.model.BIDOtpVerifyResult;
import com.bidsdk.model.BIDSD;
import com.bidsdk.model.BIDTenantInfo;
import com.bidsdk.utils.InMemCache;
import com.bidsdk.utils.WTM;
import com.google.gson.Gson;

public class BIDOTP {
	
	private static final int INTERVAL = 30;
    private static final int PASS_CODE_LENGTH = 6;
    private static final String CRYPTO = "HmacSHA1";
    private static final long ttl = 30 * 60 * 1000;
	
    public static BIDOtpResponse requestOTP(BIDTenantInfo tenantInfo, String userId, String emailOrNull, String phoneOrNull, String isdCodeOrNull) {
        BIDOtpResponse ret = null;
        try {
            BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
            BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
            String licenseKey = tenantInfo.licenseKey;
            BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);

            Map<String, Object> body = new HashMap<>();
            body.put("userId", userId);
            body.put("tenantId", communityInfo.tenant.id);
            body.put("communityId", communityInfo.community.id);


            if (emailOrNull != null) {
                body.put("emailTo", emailOrNull);
            }

            if (phoneOrNull != null && isdCodeOrNull != null) {
                body.put("smsTo", phoneOrNull);
                body.put("smsISDCode", isdCodeOrNull);
            }

            String sharedKey = BIDECDSA.createSharedKey(keySet.privateKey, communityInfo.community.publicKey);

            Map<String, String> headers = WTM.defaultHeaders();
            headers.put("licensekey", BIDECDSA.encrypt(licenseKey, sharedKey));
            headers.put("requestid", BIDECDSA.encrypt(new Gson().toJson(WTM.makeRequestId()), sharedKey));
            headers.put("publickey", keySet.publicKey);

            Boolean keepAlive = false;
            
            Map<String, Object> response = WTM.execute("post",
                                                    sd.adminconsole + "/api/r2/otp/generate",
                                                    headers,
                                                    new Gson().toJson(body),
                                                    keepAlive);

            String responseStr = (String) response.get("response");
            int statusCode = (Integer) response.get("status");

            if (statusCode == HttpStatus.SC_OK || statusCode == HttpStatus.SC_ACCEPTED) {
                ret = new Gson().fromJson(responseStr, BIDOtpResponse.class);
            }

            if (ret != null && ret.data != null) {
                String dataStr = BIDECDSA.decrypt(ret.data, sharedKey);

                ret.response = new Gson().fromJson(dataStr, BIDOtpValue.class);
            }
        }
        catch (Exception e) {
            e.printStackTrace();
        }

        return ret;
    }

    public static BIDOtpVerifyResult verifyOTP(BIDTenantInfo tenantInfo, String userId, String otpCode) {
        BIDOtpVerifyResult ret = null;
        try {
            BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
            BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
            String licenseKey = tenantInfo.licenseKey;
            BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);

            Map<String, Object> body = new HashMap<>();
            body.put("userId", userId);
            body.put("code", otpCode);
            body.put("tenantId", communityInfo.tenant.id);
            body.put("communityId", communityInfo.community.id);

            String sharedKey = BIDECDSA.createSharedKey(keySet.privateKey, communityInfo.community.publicKey);

            Map<String, String> headers = WTM.defaultHeaders();
            headers.put("licensekey", BIDECDSA.encrypt(licenseKey, sharedKey));
            headers.put("requestid", BIDECDSA.encrypt(new Gson().toJson(WTM.makeRequestId()), sharedKey));
            headers.put("publickey", keySet.publicKey);

            Boolean keepAlive = false;
            
            Map<String, Object> response = WTM.execute("post",
                    sd.adminconsole + "/api/r2/otp/verify",
                    headers,
                    new Gson().toJson(body),
                    keepAlive);

            String responseStr = (String) response.get("response");
            int statusCode = (Integer) response.get("status");

            ret = new Gson().fromJson(responseStr, BIDOtpVerifyResult.class);

        }
        catch (Exception e) {
            e.printStackTrace();
        }

        return ret;

    }
    
    public static Boolean validateOTP(String otp, String seed, Integer timeSkew) throws Exception {
        
    	long currentInterval = getCurrentInterval();
        Boolean matched = false;
        
        do {
        	String skewedHash = generateOTPWithSkew(seed, currentInterval);
        	currentInterval -= 1;
        	timeSkew 		-= 30;


        	if (skewedHash.equalsIgnoreCase(otp)) {
        		matched = true;
        		break;
        	}
        } while (timeSkew > 0);

        if (matched && isAlreadyUsed(otp, seed)) {
        	matched = false;
        }
        return matched;
    }
    
    private static long getCurrentInterval() {
		long currentTimeSeconds = System.currentTimeMillis() / 1000;
		return currentTimeSeconds / INTERVAL;
	}
	
    private static String generateOTPWithSkew(String seed, long timeInSeconds) {
        Long totp = makeOTP(seed, timeInSeconds);
        int length = String.valueOf(totp).length();
        String TOTP = Long.toString(totp);
        if (length == 5) {
            TOTP = "0" + totp;
        }
        if (length == 4) {
            TOTP = "00" + totp;
        }
        if (length == 3) {
            TOTP = "000" + totp;
        }
        if (length == 2) {
            TOTP = "0000" + totp;
        }
        return TOTP;

    }
    
    private static long makeOTP(String seed, long timeInSeconds) {
        seed = seed.trim();
        Base32 codec = new Base32();
        byte[] encodeStr = codec.encode(seed.getBytes());
        byte[] decodedKey = codec.decode(encodeStr);
        long hash = TOTP.generateTOTP(decodedKey, timeInSeconds, PASS_CODE_LENGTH, CRYPTO);
        return hash;
    }
    
    private static boolean isAlreadyUsed(String otp, String seed) {
    	String otpHash = UtilityClass.get_SHA_512(otp, seed);
    	InMemCache cache = InMemCache.getInstance();
    	if(!UtilityClass.isValidString(cache.get(otpHash))) {
    		cache.set(otpHash, seed, ttl);
    		return false;
    	}
    	return true;
    }

}

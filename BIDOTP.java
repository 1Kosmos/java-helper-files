/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */
package com.bidsdk;

import com.bidsdk.model.*;
import com.bidsdk.utils.WTM;
import com.google.gson.Gson;
import org.apache.http.HttpStatus;

import java.util.HashMap;
import java.util.Map;

public class BIDOTP {
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
}

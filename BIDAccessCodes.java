/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of this license at
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */
package com.bidsdk;

import com.bidsdk.model.BIDCommunityInfo;
import com.bidsdk.model.BIDKeyPair;
import com.bidsdk.model.BIDSD;
import com.bidsdk.model.BIDTenantInfo;
import com.bidsdk.model.BIDRequestEmailVerificationLinkResponse;
import com.bidsdk.model.BIDAccessCodeResponse;
import com.bidsdk.model.BIDRedeemEmailVerificationCodeResponse;
import com.bidsdk.utils.WTM;
import com.google.gson.Gson;
import java.util.HashMap;
import java.util.Map;

public class BIDAccessCodes {
    public static BIDRequestEmailVerificationLinkResponse requestEmailVerificationLink(BIDTenantInfo tenantInfo, String emailTo, String emailTemplateB64OrNull, String emailSubjectOrNull, String createdBy, String ttl_seconds_or_null) {
    	BIDRequestEmailVerificationLinkResponse ret = null;
        try {
            if (emailTo == null || emailTo.length() == 0) {
            	BIDRequestEmailVerificationLinkResponse errorData = new BIDRequestEmailVerificationLinkResponse();
            	errorData.statusCode = 400;
            	errorData.message = "emailTo is required parameter";
                return errorData;
            }
            
            BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
            BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
            String licenseKey = tenantInfo.licenseKey;
            BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);

            String communityPublicKey = communityInfo.community.publicKey;

            String sharedKey = BIDECDSA.createSharedKey(keySet.privateKey, communityPublicKey);

            Map < String, String > headers = WTM.defaultHeaders();
            headers.put("licensekey", BIDECDSA.encrypt(licenseKey, sharedKey));
            headers.put("X-tenantTag", communityInfo.tenant.tenanttag);
            headers.put("requestid", BIDECDSA.encrypt(new Gson().toJson(WTM.makeRequestId()), sharedKey));
            headers.put("publickey", keySet.publicKey);

            Map<String, Object> body = new HashMap<>();
            body.put("createdBy", createdBy);
            body.put("version", "v0");
            body.put("type", "verification_link");
            body.put("emailTo", emailTo);

            if (ttl_seconds_or_null != null) {
                body.put("ttl_seconds", ttl_seconds_or_null);
            }
            
            if (emailTemplateB64OrNull != null) {
                body.put("emailTemplateB64", emailTemplateB64OrNull);
            }
            
            if (emailSubjectOrNull != null) {
                body.put("emailSubject", emailSubjectOrNull);
            }

            String enc_data = BIDECDSA.encrypt(new Gson().toJson(body), sharedKey);

            Map<String, Object> data = new HashMap<>();
            data.put("data", enc_data);

            Boolean keepAlive = false;
            Map < String, Object > response = WTM.execute("put",
                sd.adminconsole + "/api/r2/acr/community/" + communityInfo.community.name + "/code",
                headers,
                new Gson().toJson(data),
                keepAlive
            );
            
            int statusCode = (Integer) response.get("status");
            
            String responseStr = (String) response.get("response");

            ret = new Gson().fromJson(responseStr, BIDRequestEmailVerificationLinkResponse.class);
            
            ret.statusCode = statusCode;
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret;
    }

    private static BIDAccessCodeResponse fetchAccessCode(BIDTenantInfo tenantInfo, String code) {
        BIDAccessCodeResponse ret = null;
        try {
            BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
            BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
            String licenseKey = tenantInfo.licenseKey;
            BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);

            String communityPublicKey = communityInfo.community.publicKey;

            String sharedKey = BIDECDSA.createSharedKey(keySet.privateKey, communityPublicKey);

            Map < String, String > headers = WTM.defaultHeaders();
            headers.put("licensekey", BIDECDSA.encrypt(licenseKey, sharedKey));
            headers.put("X-tenantTag", communityInfo.tenant.tenanttag);
            headers.put("requestid", BIDECDSA.encrypt(new Gson().toJson(WTM.makeRequestId()), sharedKey));
            headers.put("publickey", keySet.publicKey);

            Boolean keepAlive = false;
            
            Map < String, Object > response = WTM.execute("get",
                sd.adminconsole + "/api/r1/acr/community/" + communityInfo.community.name + "/" + code,
                headers,
                null,
                keepAlive
            );

            int statusCode = (Integer) response.get("status");

            String responseStr = (String) response.get("response");

            ret = new Gson().fromJson(responseStr, BIDAccessCodeResponse.class);

            if (ret.data != null) {
                String dec_data = BIDECDSA.decrypt(ret.data, sharedKey);
                ret = new Gson().fromJson(dec_data, BIDAccessCodeResponse.class);
            }

            ret.statusCode = statusCode;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret;
    }

    public static BIDAccessCodeResponse verifyAndRedeemEmailVerificationCode(BIDTenantInfo tenantInfo, String code) {
        BIDAccessCodeResponse ret = null;
        try {
            BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
            BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
            String licenseKey = tenantInfo.licenseKey;
            BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);

            String communityPublicKey = communityInfo.community.publicKey;

            ret = fetchAccessCode(tenantInfo, code);

            if (ret.statusCode != 200) {
                return ret;
            }

            if (!ret.type.equals("verification_link")) {
                ret.statusCode = 400;
                ret.message = "Provided verification code is invalid type";
                return ret;
            }

            String sharedKey = BIDECDSA.createSharedKey(keySet.privateKey, communityPublicKey);

            Map < String, String > headers = WTM.defaultHeaders();
            headers.put("licensekey", BIDECDSA.encrypt(licenseKey, sharedKey));
            headers.put("X-tenantTag", communityInfo.tenant.tenanttag);
            headers.put("requestid", BIDECDSA.encrypt(new Gson().toJson(WTM.makeRequestId()), sharedKey));
            headers.put("publickey", keySet.publicKey);

            String body = new String("{}");

            Boolean keepAlive = false;
            
            Map < String, Object > response = WTM.execute("post",
                sd.adminconsole + "/api/r1/acr/community/" + communityInfo.community.name + "/" + code + "/redeem",
                headers,
                body,
                keepAlive
            );

            int statusCode = (Integer) response.get("status");

            String responseStr = (String) response.get("response");
            BIDRedeemEmailVerificationCodeResponse redemCodeResponse = new Gson().fromJson(responseStr, BIDRedeemEmailVerificationCodeResponse.class);

            if (statusCode == 200) {
                ret.message = redemCodeResponse.message;
                ret.status = "redeemed";
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret;
    }
}

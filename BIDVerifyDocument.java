/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of this license at
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */
package com.bidsdk;

import com.bidsdk.model.BIDCommunityInfo;
import com.bidsdk.model.BIDCreateDocumentSessionResponse;
import com.bidsdk.model.BIDKeyPair;
import com.bidsdk.model.BIDPollSessionResponse;
import com.bidsdk.model.BIDSD;
import com.bidsdk.model.BIDTenantInfo;
import com.bidsdk.model.BIDVerifyDocumentResponse;
import com.bidsdk.utils.InMemCache;
import com.bidsdk.utils.WTM;
import com.google.gson.Gson;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class BIDVerifyDocument {

    private static String getPublicKey(BIDTenantInfo tenantInfo) {
        String ret = null;
        try {
            BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);
            String url = sd.docuverify + "/publickeys";

            String cache_key = url;
            String cache_str = InMemCache.getInstance().get(cache_key);
            if (cache_str != null) {
                Map < String, String > map = new Gson().fromJson(cache_str, Map.class);
                ret = map.get("publicKey");
                return ret;
            }

            //load from services
            Map < String, Object > response = WTM.execute(
                "get",
                url,
                WTM.defaultHeaders(),
                null
            );
            String responseStr = (String) response.get("response");

            int statusCode = (Integer) response.get("status");
            if (statusCode == 200) {
                Map < String, String > map = new Gson().fromJson(responseStr, Map.class);
                ret = map.get("publicKey");
                InMemCache.getInstance().set(cache_key, responseStr);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return ret;
    }

    public static BIDVerifyDocumentResponse verifyDocument(
        BIDTenantInfo tenantInfo,
        String dvcId,
        String[] verifications,
        Object document
    ) {
        BIDVerifyDocumentResponse ret = null;
        try {

            BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
            String licenseKey = tenantInfo.licenseKey;
            BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);

            String docVerifyPublicKey = getPublicKey(tenantInfo);

            String sharedKey = BIDECDSA.createSharedKey(keySet.privateKey, docVerifyPublicKey);

            Map < String, String > headers = WTM.defaultHeaders();
            headers.put("licensekey", BIDECDSA.encrypt(licenseKey, sharedKey));
            headers.put("requestid", BIDECDSA.encrypt(new Gson().toJson(WTM.makeRequestId()), sharedKey));
            headers.put("publickey", keySet.publicKey);

            Map < String, Object > body = new HashMap < > ();
            body.put("dvcID", dvcId);
            body.put("verifications", verifications);
            body.put("document", document);

            String enc_data = BIDECDSA.encrypt(new Gson().toJson(body), sharedKey);

            Map < String, Object > data = new HashMap < > ();
            data.put("data", enc_data);

            Map < String, Object > response = WTM.execute("post",
                sd.docuverify + "/verify",
                headers,
                new Gson().toJson(data)
            );

            String responseStr = (String) response.get("response");

            ret = new Gson().fromJson(responseStr, BIDVerifyDocumentResponse.class);

            if (ret.data != null) {
                String dec_data = BIDECDSA.decrypt(ret.data, sharedKey);
                ret = new Gson().fromJson(dec_data, BIDVerifyDocumentResponse.class);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret;
    }

    public static BIDCreateDocumentSessionResponse createDocumentSession(BIDTenantInfo tenantInfo, String dvcId, String documentType) {
        BIDCreateDocumentSessionResponse ret = null;
        try {
            BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
            BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
            String licenseKey = tenantInfo.licenseKey;
            BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);

            String docVerifyPublicKey = getPublicKey(tenantInfo);

            String sharedKey = BIDECDSA.createSharedKey(keySet.privateKey, docVerifyPublicKey);

            Map < String, String > headers = WTM.defaultHeaders();
            headers.put("licensekey", BIDECDSA.encrypt(licenseKey, sharedKey));
            headers.put("requestid", BIDECDSA.encrypt(new Gson().toJson(WTM.makeRequestId()), sharedKey));
            headers.put("publickey", keySet.publicKey);

            String userUIDAndDid = UUID.randomUUID().toString();

            Map < String, Object > sessionRequest = new HashMap < > ();
            sessionRequest.put("tenantDNS", tenantInfo.dns);
            sessionRequest.put("communityName", communityInfo.community.name);
            sessionRequest.put("documentType", documentType);
            sessionRequest.put("userUID", userUIDAndDid);
            sessionRequest.put("did", userUIDAndDid);

            Map < String, Object > body = new HashMap < > ();
            body.put("dvcID", dvcId);
            body.put("sessionRequest", sessionRequest);

            String enc_data = BIDECDSA.encrypt(new Gson().toJson(body), sharedKey);

            Map < String, Object > data = new HashMap < > ();
            data.put("data", enc_data);

            Map < String, Object > response = WTM.execute("post",
                sd.docuverify + "/document_share_session/create",
                headers,
                new Gson().toJson(data));

            String responseStr = (String) response.get("response");

            ret = new Gson().fromJson(responseStr, BIDCreateDocumentSessionResponse.class);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret;
    }

    public static BIDPollSessionResponse pollSessionResult(BIDTenantInfo tenantInfo, String dvcId, String sessionId) {
        BIDPollSessionResponse ret = null;
        try {
            BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
            String licenseKey = tenantInfo.licenseKey;
            BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);

            String docVerifyPublicKey = getPublicKey(tenantInfo);

            String sharedKey = BIDECDSA.createSharedKey(keySet.privateKey, docVerifyPublicKey);

            Map < String, String > headers = WTM.defaultHeaders();
            headers.put("licensekey", BIDECDSA.encrypt(licenseKey, sharedKey));
            headers.put("requestid", BIDECDSA.encrypt(new Gson().toJson(WTM.makeRequestId()), sharedKey));
            headers.put("publickey", keySet.publicKey);

            Map < String, Object > body = new HashMap < > ();
            body.put("dvcID", dvcId);
            body.put("sessionId", sessionId);

            String enc_data = BIDECDSA.encrypt(new Gson().toJson(body), sharedKey);

            Map < String, Object > data = new HashMap < > ();
            data.put("data", enc_data);

            Map < String, Object > response = WTM.execute("post",
                sd.docuverify + "/document_share_session/result",
                headers,
                new Gson().toJson(data)
            );

            String responseStr = (String) response.get("response");

            ret = new Gson().fromJson(responseStr, BIDPollSessionResponse.class);

            if (ret.data != null) {
                String dec_data = BIDECDSA.decrypt(ret.data, sharedKey);
                ret = new Gson().fromJson(dec_data, BIDPollSessionResponse.class);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret;
    }
}

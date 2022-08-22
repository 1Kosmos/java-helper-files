/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */
package com.bidsdk;

import com.bidsdk.model.*;
import com.bidsdk.utils.InMemCache;
import com.bidsdk.utils.WTM;
import com.google.gson.Gson;
import org.apache.http.HttpStatus;

import java.util.HashMap;
import java.util.Map;

public class BIDSessions {
    private static String getPublicKey(BIDTenantInfo tenantInfo) {
        String ret = null;
        try {
            BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);
            String url = sd.sessions + "/publickeys";

            String cache_key = url;
            String cache_str = InMemCache.getInstance().get(cache_key);
            if (cache_str != null) {
                Map<String, String> map = new Gson().fromJson(cache_str, Map.class);
                ret = map.get("publicKey");
                return ret;
            }

            //load from services
            Map<String, Object> response = WTM.execute("get"
                                            , url
                                            , WTM.defaultHeaders()
                                            , null);
            String responseStr = (String) response.get("response");
            int statusCode = (Integer) response.get("status");
            if (statusCode == 200) {
                Map<String, String> map = new Gson().fromJson(responseStr, Map.class);
                ret = map.get("publicKey");
                InMemCache.getInstance().set(cache_key, responseStr);
            }
        }
        catch (Exception e) {
            e.printStackTrace();
        }

        return ret;
    }

    public static BIDSession createNewSession(BIDTenantInfo tenantInfo, String authType, String scopes) {
        BIDSession ret = null;
        try {
            BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
            BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
            String licenseKey = tenantInfo.licenseKey;
            BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);

            String sessionsPublicKey = getPublicKey(tenantInfo);


            Map<String, Object> origin = new HashMap<>();
            origin.put("tag" , communityInfo.tenant.tenanttag);
            origin.put("url", sd.adminconsole);
            origin.put("communityName", communityInfo.community.name);
            origin.put("communityId", communityInfo.community.id);
            origin.put("authPage", "blockid://authenticate");

            Map<String, Object> body = new HashMap<>();
            body.put("origin", origin);
            body.put("scopes", (scopes != null) ? scopes : "");
            body.put("authtype", (authType != null) ? authType : "none");

            String sharedKey = BIDECDSA.createSharedKey(keySet.privateKey, sessionsPublicKey);

            Map<String, String> headers = WTM.defaultHeaders();
            headers.put("licensekey", BIDECDSA.encrypt(licenseKey, sharedKey));
            headers.put("requestid", BIDECDSA.encrypt(new Gson().toJson(WTM.makeRequestId()), sharedKey));
            headers.put("publickey", keySet.publicKey);

            Map<String, Object> response = WTM.execute("put",
                    sd.sessions + "/session/new",
                    headers,
                    new Gson().toJson(body));


            String responseStr = (String) response.get("response");
            int statusCode = (Integer) response.get("status");

            ret = new Gson().fromJson(responseStr, BIDSession.class);
            ret.url = sd.sessions;
        }
        catch (Exception e) {

        }
        return ret;
    }

    public static BIDSessionResponse pollSession(BIDTenantInfo tenantInfo, String sessionId, boolean fetchProfile, boolean fetchDevices) {
        BIDSessionResponse ret = null;
        try {
            BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
            BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
            String licenseKey = tenantInfo.licenseKey;
            BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);

            String sessionsPublicKey = getPublicKey(tenantInfo);

            String sharedKey = BIDECDSA.createSharedKey(keySet.privateKey, sessionsPublicKey);

            Map<String, String> headers = WTM.defaultHeaders();
            headers.put("licensekey", BIDECDSA.encrypt(licenseKey, sharedKey));
            headers.put("requestid", BIDECDSA.encrypt(new Gson().toJson(WTM.makeRequestId()), sharedKey));
            headers.put("publickey", keySet.publicKey);

            Map<String, Object> response = WTM.execute("get",
                    sd.sessions + "/session/" + sessionId + "/response",
                    headers,
                    null);

            String responseStr = (String) response.get("response");
            int statusCode = (Integer) response.get("status");

            if (statusCode != HttpStatus.SC_OK) {
                ret = new BIDSessionResponse();
                ret.status = statusCode;
                ret.message = responseStr;
                return ret;
            }

            ret = new Gson().fromJson(responseStr, BIDSessionResponse.class);
            ret.status = statusCode;

            if (ret.data != null) {
                String clientSharedKey = BIDECDSA.createSharedKey(keySet.privateKey, ret.publicKey);
                String dec_data = BIDECDSA.decrypt(ret.data, clientSharedKey);
                ret.user_data = new Gson().fromJson(dec_data, Map.class);
            }

            if (ret != null && ret.data != null && ret.user_data.containsKey("did") && fetchProfile) {
                ret.account_data = BIDUsers.fetchUserByDID(tenantInfo, (String)ret.user_data.get("did"), fetchDevices);
            }
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return ret;

    }
}

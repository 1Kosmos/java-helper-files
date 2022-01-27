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
import com.bidsdk.model.BIDPoNData;
import com.bidsdk.model.BIDSD;
import com.bidsdk.utils.WTM;
import com.google.gson.Gson;

import java.util.Map;

public class BIDUsers {
    public static BIDPoNData fetchUserByDID(String did, boolean fetchDevices) {
        BIDPoNData ret = null;
        try {
            BIDCommunityInfo communityInfo = BIDSDK.getInstance().getCommunityInfo();
            BIDKeyPair keySet = BIDSDK.getInstance().getKeySet();
            String licenseKey = BIDSDK.getInstance().getLicenseKey();
            BIDSD sd = BIDSDK.getInstance().getSD();

            String sharedKey = BIDECDSA.createSharedKey(keySet.privateKey, communityInfo.community.publicKey);

            Map<String, String> headers = WTM.defaultHeaders();
            headers.put("licensekey", BIDECDSA.encrypt(licenseKey, sharedKey));
            headers.put("requestid", BIDECDSA.encrypt(new Gson().toJson(WTM.makeRequestId()), sharedKey));
            headers.put("publickey", keySet.publicKey);
            headers.put("X-TenantTag", communityInfo.tenant.tenanttag);

            String url = sd.adminconsole + "/api/r1/community/" + communityInfo.community.name + "/userdid/" + did + "/userinfo";
            if (fetchDevices) {
                url = url + "?devicelist=true";
            }

            Map<String, Object> response = WTM.execute("get",
                    url,
                    headers,
                    null);


            String responseStr = (String) response.get("response");
            int statusCode = (Integer) response.get("status");

            Map<String, String> map = new Gson().fromJson(responseStr, Map.class);

            String dec_data = BIDECDSA.decrypt(map.get("data"), sharedKey);
            ret = new Gson().fromJson(dec_data, BIDPoNData.class);

        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return ret;
    }
}

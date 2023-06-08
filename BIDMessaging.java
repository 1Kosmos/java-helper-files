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
import com.bidsdk.model.BIDSendSMSResponse;
import com.bidsdk.model.BIDTenantInfo;
import com.bidsdk.utils.WTM;
import com.google.gson.Gson;
import java.util.HashMap;
import java.util.Map;

public class BIDMessaging {
    public static BIDSendSMSResponse sendSMS(BIDTenantInfo tenantInfo, String smsTo, String smsISDCode, String smsTemplateB64) {
        BIDSendSMSResponse ret = null;
        try {
            BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
            BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
            String licenseKey = tenantInfo.licenseKey;
            BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);

            String communityPublicKey = communityInfo.community.publicKey;

            String sharedKey = BIDECDSA.createSharedKey(keySet.privateKey, communityPublicKey);

            Map < String, String > headers = WTM.defaultHeaders();
            headers.put("licensekey", BIDECDSA.encrypt(licenseKey, sharedKey));
            headers.put("requestid", BIDECDSA.encrypt(new Gson().toJson(WTM.makeRequestId()), sharedKey));
            headers.put("publickey", keySet.publicKey);

            Map < String, Object > body = new HashMap < > ();
            body.put("tenantId", communityInfo.community.tenantid);
            body.put("communityId", communityInfo.community.id);
            body.put("smsTo", smsTo);
            body.put("smsISDCode", smsISDCode);
            body.put("smsTemplateB64", smsTemplateB64);

            Boolean keepAlive = false;
            
            Map < String, Object > response = WTM.execute("post",
                sd.adminconsole + "/api/r2/messaging/schedule",
                headers,
                new Gson().toJson(body),
                keepAlive
            );

            String responseStr = (String) response.get("response");

            ret = new Gson().fromJson(responseStr, BIDSendSMSResponse.class);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret;
    }
}

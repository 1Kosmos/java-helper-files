/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of this license at
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */
package com.bidsdk;

import com.bidsdk.model.BIDAttestationOptionsResponse;
import com.bidsdk.model.BIDAttestationOptionsValue;
import com.bidsdk.model.BIDAttestationResultData;
import com.bidsdk.model.BIDAttestationResultResponseValue;
import com.bidsdk.model.BIDAttestationResultValue;
import com.bidsdk.model.BIDCommunityInfo;
import com.bidsdk.model.BIDKeyPair;
import com.bidsdk.model.BIDSD;
import com.bidsdk.model.BIDTenantInfo;
import com.bidsdk.model.BIDAssertionOptionValue;
import com.bidsdk.model.BIDAssertionOptionResponse;
import com.bidsdk.model.BIDAssertionResultValue;
import com.bidsdk.model.BIDAssertionResultResponse;
import com.bidsdk.utils.InMemCache;
import com.bidsdk.utils.WTM;
import com.google.gson.Gson;
import java.util.HashMap;
import java.util.Map;

public class BIDWebAuthn {

  public static BIDAttestationOptionsResponse fetchAttestationOptions(
    BIDTenantInfo tenantInfo,BIDAttestationOptionsValue attestationOptionsRequest
  ) {
    BIDAttestationOptionsResponse ret = null;
    try {
      BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
      BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
      String licenseKey = tenantInfo.licenseKey;
      BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);

      Map<String, String> headers = WTM.defaultHeaders();
      headers.put("licensekey", licenseKey);
      headers.put("requestid", new Gson().toJson(WTM.makeRequestId()));
      headers.put("publickey", keySet.publicKey);

      Map<String, Object> body = new HashMap<>();
      body.put("dns", attestationOptionsRequest.dns);
      body.put("username", attestationOptionsRequest.username);
      body.put("displayName", attestationOptionsRequest.displayName);
      body.put("attestation", attestationOptionsRequest.attestation);
      body.put("authenticatorSelection", attestationOptionsRequest.authenticatorSelection);
      body.put("communityId", communityInfo.community.id);
      body.put("tenantId", communityInfo.tenant.id);

      Map<String, Object> response = WTM.execute("post",
        sd.webauthn + "/u1/attestation/options",
        headers,
        new Gson().toJson(body)
      );

      String responseStr = (String) response.get("response");

      ret = new Gson().fromJson(responseStr, BIDAttestationOptionsResponse.class);

    } catch (Exception e) {
      e.printStackTrace();
    }
    return ret;
  }

  public static BIDAttestationResultData submitAttestationResult(BIDTenantInfo tenantInfo, BIDAttestationResultValue attestationResultRequest) {
    BIDAttestationResultData ret = null;
    try {
      BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
      BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
      String licenseKey = tenantInfo.licenseKey;
      BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);

      Map<String, String> headers = WTM.defaultHeaders();
      headers.put("licensekey", licenseKey);
      headers.put("requestid", new Gson().toJson(WTM.makeRequestId()));
      headers.put("publickey", keySet.publicKey);

      Map<String, Object> body = new HashMap<>();
      body.put("rawId", attestationResultRequest.rawId);
      body.put("response", attestationResultRequest.response);
      body.put("authenticatorAttachment", attestationResultRequest.authenticatorAttachment);
      body.put("getClientExtensionResults", attestationResultRequest.getClientExtensionResults);
      body.put("id", attestationResultRequest.id);
      body.put("type", attestationResultRequest.type);
      body.put("dns", attestationResultRequest.dns);
      body.put("communityId", communityInfo.community.id);
      body.put("tenantId", communityInfo.tenant.id);

      Map<String, Object> response = WTM.execute("post",
        sd.webauthn + "/u1/attestation/result",
        headers,
        new Gson().toJson(body)
      );

      String responseStr = (String) response.get("response");

      ret = new Gson().fromJson(responseStr, BIDAttestationResultData.class);
      
    } catch (Exception e) {
      e.printStackTrace();
    }
    return ret;
  }

  public static BIDAssertionOptionResponse fetchAssertionOptions(BIDTenantInfo tenantInfo, BIDAssertionOptionValue assertionOptionRequest) {
    BIDAssertionOptionResponse ret = null;
    try {
      BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
      BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
      String licenseKey = tenantInfo.licenseKey;
      BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);

      Map<String, String> headers = WTM.defaultHeaders();
      headers.put("licensekey", licenseKey);
      headers.put("requestid", new Gson().toJson(WTM.makeRequestId()));
      headers.put("publickey", keySet.publicKey);

      Map<String, Object> body = new HashMap<>();
      body.put("username", assertionOptionRequest.username);
      body.put("displayName", assertionOptionRequest.displayName);
      body.put("dns", assertionOptionRequest.dns);
      body.put("communityId", communityInfo.community.id);
      body.put("tenantId", communityInfo.tenant.id);

      Map<String, Object> response = WTM.execute("post",
        sd.webauthn + "/u1/assertion/options",
        headers,
        new Gson().toJson(body)
      );

      String responseStr = (String) response.get("response");

      ret = new Gson().fromJson(responseStr, BIDAssertionOptionResponse.class);
      
    } catch (Exception e) {
      e.printStackTrace();
    }
    return ret;
  }

  public static BIDAssertionResultResponse submitAssertionResult(BIDTenantInfo tenantInfo, BIDAssertionResultValue assertionResultRequest) {
    BIDAssertionResultResponse ret = null;
    try {
      BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
      BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
      String licenseKey = tenantInfo.licenseKey;
      BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);

      Map<String, String> headers = WTM.defaultHeaders();
      headers.put("licensekey", licenseKey);
      headers.put("requestid", new Gson().toJson(WTM.makeRequestId()));
      headers.put("publickey", keySet.publicKey);

      Map<String, Object> body = new HashMap<>();
      body.put("rawId", assertionResultRequest.rawId);
      body.put("dns", assertionResultRequest.dns);
      body.put("response", assertionResultRequest.response);
      body.put("getClientExtensionResults", assertionResultRequest.getClientExtensionResults);
      body.put("id", assertionResultRequest.id);
      body.put("type", assertionResultRequest.type);
      body.put("communityId", communityInfo.community.id);
      body.put("tenantId", communityInfo.tenant.id);

      Map<String, Object> response = WTM.execute("post",
        sd.webauthn + "/u1/assertion/result",
        headers,
        new Gson().toJson(body)
      );

      String responseStr = (String) response.get("response");

      ret = new Gson().fromJson(responseStr, BIDAssertionResultResponse.class);
      
    } catch (Exception e) {
      e.printStackTrace();
    }
    return ret;
  }
}

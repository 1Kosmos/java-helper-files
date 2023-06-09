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
import com.bidsdk.utils.InMemCache;
import com.bidsdk.utils.WTM;
import com.google.gson.Gson;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;

public class BIDTenant {

  private static final BIDTenant instance = new BIDTenant();

  public BIDTenant() {}

  public static BIDTenant getInstance() {
    return instance;
  }

  private BIDKeyPair keySet;

  public BIDCommunityInfo getCommunityInfo(BIDTenantInfo tenantInfo) { BIDCommunityInfo communityInfo = null;
    try {
      Map<String, Object> body = new HashMap<>();

      String cache_key = "communityCache_" + tenantInfo.dns;

      if (tenantInfo.tenantId != null) {
        body.put("tenantId", tenantInfo.tenantId);
        cache_key = cache_key + "_" + tenantInfo.tenantId;
      } else {
        body.put("dns", tenantInfo.dns);
      }

      if (tenantInfo.communityId != null) {
        body.put("communityId", tenantInfo.communityId);
        cache_key = cache_key + "_" + tenantInfo.communityId;
      } else {
        body.put("communityName", tenantInfo.communityName);
        cache_key = cache_key + "_" + tenantInfo.communityName;
      }

      String cache_str = InMemCache.getInstance().get(cache_key);

      if (cache_str != null) {
        communityInfo = new Gson().fromJson(cache_str, BIDCommunityInfo.class);
        return communityInfo;
      }

      String url = "https://" + tenantInfo.dns + "/api/r1/system/community_info/fetch";

      Boolean keepAlive = false;
      
      Map<String, Object> response = WTM.execute(
        "post",
        url,
        WTM.defaultHeaders(),
        new Gson().toJson(body),
        keepAlive
      );

      String responseStr = (String) response.get("response");
      int statusCode = (Integer) response.get("status");

      if (statusCode == HttpStatus.SC_OK) {
        InMemCache.getInstance().set(cache_key, responseStr);
        communityInfo = new Gson().fromJson(responseStr, BIDCommunityInfo.class);
      } else {
        throw new Exception("Unable to load communityInfo code" + statusCode + " with message: " + responseStr);
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
    return communityInfo;
  }

  public BIDSD getSD(BIDTenantInfo tenantInfo) {
    BIDSD sd = null;

    try {
      String cache_key = "sdCache_" + tenantInfo.dns;

      if (tenantInfo.tenantId != null) {
        cache_key = cache_key + "_" + tenantInfo.tenantId;
      }

      if (tenantInfo.communityId != null) {
        cache_key = cache_key + "_" + tenantInfo.communityId;
      } else {
        cache_key = (tenantInfo.communityName != null) ? cache_key + "_" + tenantInfo.communityName : cache_key;
      }

      String sdUrl = "https://" + tenantInfo.dns + "/caas/sd";

      String cache_str = InMemCache.getInstance().get(cache_key);
      if (cache_str != null) {
        sd = new Gson().fromJson(cache_str, BIDSD.class);
        return sd;
      }
      
      Boolean keepAlive = true;

      Map<String, Object> response = WTM.execute(
        "get",
        sdUrl,
        WTM.defaultHeaders(),
        null,
        keepAlive
      );

      String responseStr = (String) response.get("response");
      int statusCode = (Integer) response.get("status");

      if (statusCode == HttpStatus.SC_OK) {
        sd = new Gson().fromJson(responseStr, BIDSD.class);
        InMemCache.getInstance().set(cache_key, responseStr);
      } else {
        throw new Exception(
          "Unable to load sd code" +
          statusCode +
          " with message: " +
          responseStr
        );
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
    return sd;
  }

  public BIDKeyPair getKeySet() {
    try{
    if (this.keySet == null) {
      this.keySet = BIDECDSA.generateKeyPair();
    }
     } catch (Exception e) {
      e.printStackTrace();
    }
    return keySet;
  }

  public void setKeySet(BIDKeyPair keySet) {
    this.keySet = keySet;
  }
}

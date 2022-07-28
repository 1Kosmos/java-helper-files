/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */
package com.bidsdk.model;

import com.google.gson.Gson;

public class BIDAccessCodeResponse {
	public Integer ttl_seconds;
	public String type;
	public Boolean phoneRequired;
	public String uuid;
	public Integer ttl;
	public Integer createdTime;
	public String tenantId;
	public String communityId;
	public String id;
    public String data;
    public String publickey;
    public String status;
    public Integer statusCode;
	public String message;
    public BIDAccesscodepayloadData accesscodepayload;

    @Override
    public String toString() {
        return new Gson().toJson(this);
    }
}


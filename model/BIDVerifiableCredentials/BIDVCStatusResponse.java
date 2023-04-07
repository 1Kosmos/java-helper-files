/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */
package com.bidsdk.model.BIDVerifiableCredentials;

import java.util.Map;

import com.google.gson.Gson;

public class BIDVCStatusResponse  {
	
	public int code;
	public String message;
	public Map<String, Object> result;
	
	@Override
	public String toString() {
		return new Gson().toJson(this);
	}

}

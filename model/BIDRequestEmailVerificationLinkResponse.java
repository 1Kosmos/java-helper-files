/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */
package com.bidsdk.model;

import com.google.gson.Gson;

public class BIDRequestEmailVerificationLinkResponse {
    public Integer statusCode;
    public String message;
    public BIDAccessCodeeEmailResultData emailResult;
    public String link;
    public String code;
    
    @Override
    public String toString() {
        return new Gson().toJson(this);
    }
}

# java-helper-files

# Adding java helpers to your project

- Add repo to your project (as submodule) under path: `main › java › com › bidsdk`

_(*ability* to add as gradle dependency will be added soon)_

- add to build.gradle
```
ext {
	web3jVersion = "4.5.4"
}

dependencies {

	implementation group: 'org.bitcoinj', name: 'bitcoinj-core', version: '0.15.10'
	implementation "org.web3j:core:$web3jVersion"

	implementation group: 'com.squareup.okhttp3', name: 'okhttp', version: '4.3.1'
	implementation 'org.apache.httpcomponents:httpclient:4.5.13'
	implementation 'com.google.code.gson:gson:2.8.6'
}

```

- Know your tenant (BIDTenant) `dns` and `communityName`

- Request OTP
```
BIDTenantInfo tenantInfo = new BIDTenantInfo("<dns>", "<communityName>", "<license>");

BIDOtpResponse otpResponse = BIDOTP.requestOTP(tenantInfo, "<username>", "<emailTo>", "<smsTo>", "<ISDCode>");
```

- Verify OTP
```
BIDTenantInfo tenantInfo = new BIDTenantInfo("<dns>", "<communityName>", "<license>");

BIDOtpVerifyResult result = BIDOTP.verifyOTP(tenantInfo, "<username>", "<otpcode>");
```

- Create new UWL2.0 session
```
BIDTenantInfo tenantInfo = new BIDTenantInfo("<dns>", "<communityName>", "<license>");

BIDSession session = BIDSessions.createNewSession(tenantInfo, null, null);
```

- Poll for UWL2.0 session response
```
BIDTenantInfo tenantInfo = new BIDTenantInfo("<dns>", "<communityName>", "<license>");

BIDSessionResponse response = BIDSessions.pollSession(tenantInfo, "<sessionId>", true, true);
```

- FIDO2 Registration options
```
BIDTenantInfo tenantInfo = new BIDTenantInfo("<dns>", "<communityName>", "<license>");

BIDAssertionOptionValue attestationOptionRequest = new BIDAssertionOptionValue();
attestationOptionRequest.put("dns", "<dns>");
attestationOptionRequest.put("username", "<username>");
attestationOptionRequest.put("displayName", "<displayName>");
attestationOptionRequest.put("attestation", "<attestation>");
attestationOptionRequest.put("authenticatorSelection", "<authenticatorSelection>");

BIDAttestationOptionsResponse attestationOptionsResponse = BIDWebAuthn.fetchAttestationOptions(tenantInfo, attestationOptionRequest);
```

- FIDO2 Registration result
```
BIDTenantInfo tenantInfo = new BIDTenantInfo("<dns>", "<communityName>", "<license>");

BIDAttestationResultValue attestationResultRequest = new BIDAttestationResultValue();
attestationResultRequest.put("rawId", "<rawId>");
attestationResultRequest.put("response", "<response>");
attestationResultRequest.put("authenticatorAttachment", "<authenticatorAttachment>");
attestationResultRequest.put("getClientExtensionResults", "<getClientExtensionResults>");
attestationResultRequest.put("id", "<id>");
attestationResultRequest.put("type", "<type>");
attestationResultRequest.put("dns", "<dns>");

BIDAttestationResultData attestationResultResponse = BIDWebAuthn.submitAttestationResult(tenantInfo, attestationResultRequest);
```

- Create new Driver's License verification session
```
BIDTenantInfo tenantInfo = new BIDTenantInfo("<dns>", "<communityName>", "<license>");

BIDCreateDocumentSessionResponse createdSessionResponse = BIDVerifyDocument.createDocumentSession(tenantInfo, "<dvcId>", "<documentType>");
    
```

- Trigger SMS 
```
BIDTenantInfo tenantInfo = new BIDTenantInfo("<dns>", "<communityName>", "<license>");

BIDSendSMSResponse smsResponse = BIDMessaging.sendSMS(tenantInfo, "<smsTo>", "<smsISDCode>", "<smsTemplateB64>");
```

- Poll for Driver's License session response
```
BIDTenantInfo tenantInfo = new BIDTenantInfo("<dns>", "<communityName>", "<license>");
BIDPollSessionResponse pollSessionResponse = BIDVerifyDocument.pollSessionResult(tenantInfo, "<dvcId>", "<sessionId>");
```

- Request Email verification link
```
BIDTenantInfo tenantInfo = new BIDTenantInfo("<dns>", "<communityName>", "<license>");

BIDRequestEmailVerificationLinkResponse requestEmailVerificationResponse = BIDAccessCodes.requestEmailVerificationLink(tenantInfo, "<emailTo>", "<emailTemplateB64OrNull>", "<emailSubjectOrNull>", "<ttl_seconds_or_null>");
```

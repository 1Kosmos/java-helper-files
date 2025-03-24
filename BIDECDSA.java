/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */
package com.bidsdk;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Base64;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import javax.crypto.KeyAgreement;


import com.bidsdk.model.BIDKeyPair;
import com.bidsdk.utils.EncryptDecryptLogic;


public class BIDECDSA {

    public static BIDKeyPair generateKeyPair() throws Exception {
        BIDKeyPair keyPairs = new BIDKeyPair();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC");
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256k1");
        keyPairGenerator.initialize(ecGenParameterSpec, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        BCECPrivateKey privateKey = (BCECPrivateKey) keyPair.getPrivate();
        BigInteger privateKeyValue = privateKey.getD();
        BCECPublicKey publicKeyBC = (BCECPublicKey) keyPair.getPublic();
        byte[] rawPubKeyBytes = publicKeyBC.getQ().getEncoded(false);
        byte[] pubKeyBytes = Arrays.copyOfRange(rawPubKeyBytes, 1, rawPubKeyBytes.length);
        keyPairs.privateKey = Base64.getEncoder().encodeToString(privateKeyValue.toByteArray());
        keyPairs.publicKey = Base64.getEncoder().encodeToString(pubKeyBytes);
        String sharedKey = createSharedKey(keyPairs.privateKey, keyPairs.publicKey);
        return keyPairs;
    }
    public static String encrypt(String value, String key) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        EncryptDecryptLogic encryptDecryptLogic = new EncryptDecryptLogic();
        return encryptDecryptLogic.ecdsaHelper("encrypt", value, key);
    }

    public static String decrypt(String value, String key) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        EncryptDecryptLogic encryptDecryptLogic = new EncryptDecryptLogic();
        return encryptDecryptLogic.ecdsaHelper("decrypt", value, key);
    }

    public static String createSharedKey(String prKey, String pbKey) throws Exception {
        byte[] privateKeyStr = Base64.getDecoder().decode(prKey.getBytes());
        byte[] publicKeyStr = Base64.getDecoder().decode(pbKey.getBytes());
        PrivateKey privateKey = toECPrivateKey(privateKeyStr);
        PublicKey publicKey = toEcPublicKey(publicKeyStr);
        KeyAgreement ka1 = null;
        ka1 = KeyAgreement.getInstance("ECDH");
        ka1.init(privateKey);
        ka1.doPhase(publicKey, true);
        byte[] sharedSecret1 = ka1.generateSecret();
        return Base64.getEncoder().encodeToString(sharedSecret1);
    }

    private static PrivateKey toECPrivateKey(byte[] privateKeyStr) throws Exception {
        BigInteger privKey = new BigInteger(privateKeyStr);
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECNamedCurveSpec curveSpec = new ECNamedCurveSpec("secp256k1", params.getCurve(), params.getG(),
                params.getN());
        ECPrivateKeySpec keySpec = new ECPrivateKeySpec(privKey, curveSpec);
        return keyFactory.generatePrivate(keySpec);
    }

    private static PublicKey toEcPublicKey(byte[] publicKeyByte) throws Exception {
        String publicKeyStr = byteArrayToHex(publicKeyByte);
        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECNamedCurveSpec curveSpec = new ECNamedCurveSpec("secp256k1", params.getCurve(), params.getG(),
                params.getN());
        // This is the part how to generate ECPoint manually from public key string.\
        String pubKeyX = publicKeyStr.substring(0, publicKeyStr.length() / 2);
        String pubKeyY = publicKeyStr.substring(publicKeyStr.length() / 2);
        ECPoint ecPoint = new ECPoint(new BigInteger(pubKeyX, 16), new BigInteger(pubKeyY, 16));
        ECParameterSpec params2 = EC5Util.convertSpec(curveSpec.getCurve(), params);
        ECPublicKeySpec keySpec = new ECPublicKeySpec(ecPoint, params2);
        KeyFactory factory = KeyFactory.getInstance("ECDSA");
        return factory.generatePublic(keySpec);
    }

    private static String byteArrayToHex(byte[] bytes) {
        char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

}

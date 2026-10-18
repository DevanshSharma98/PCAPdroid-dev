/*
 * This file is part of PCAPdroid.
 *
 * PCAPdroid is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
package com.emanuelef.remote_capture;

import android.content.Context;
import android.util.Base64;

import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

/** Encrypts optional provider keys with a non-exportable Android Keystore AES key. */
public final class PhantomApiKeyVault {
    private static final String PREFS = "phantom_provider_keys";
    private static final String STORE = "AndroidKeyStore";
    private static final String ALIAS = "com.emanuelef.remote_capture.phantom.api_keys";
    private PhantomApiKeyVault() {}

    public static synchronized void save(Context context, String provider, String value) throws Exception {
        if(value == null || value.trim().isEmpty()) {
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().remove(provider).apply();
            return;
        }
        SecretKey key = getOrCreateKey();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(value.trim().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String packed = Base64.encodeToString(cipher.getIV(), Base64.NO_WRAP) + "." +
                Base64.encodeToString(encrypted, Base64.NO_WRAP);
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(provider, packed).apply();
    }

    public static synchronized String get(Context context, String provider) throws Exception {
        String packed = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(provider, null);
        if(packed == null) return null;
        int split = packed.indexOf('.');
        if(split <= 0) throw new IllegalStateException("Stored provider key is malformed");
        byte[] iv = Base64.decode(packed.substring(0, split), Base64.NO_WRAP);
        byte[] encrypted = Base64.decode(packed.substring(split + 1), Base64.NO_WRAP);
        KeyStore store = KeyStore.getInstance(STORE);
        store.load(null);
        SecretKey key = (SecretKey) store.getKey(ALIAS, null);
        if(key == null) throw new IllegalStateException("Android Keystore key is unavailable; re-enter this provider key");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return new String(cipher.doFinal(encrypted), java.nio.charset.StandardCharsets.UTF_8);
    }

    private static SecretKey getOrCreateKey() throws Exception {
        KeyStore store = KeyStore.getInstance(STORE);
        store.load(null);
        if(store.containsAlias(ALIAS)) {
            SecretKey existing = (SecretKey) store.getKey(ALIAS, null);
            if(existing != null) return existing;
            store.deleteEntry(ALIAS);
        }
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, STORE);
        generator.init(new KeyGenParameterSpec.Builder(ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .setKeySize(256)
                .build());
        return generator.generateKey();
    }
}

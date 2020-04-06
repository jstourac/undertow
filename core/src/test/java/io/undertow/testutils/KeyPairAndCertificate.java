/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package io.undertow.testutils;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.x509.X509V3CertificateGenerator;

/**
 * Simple class to ease creation of keystores/truststores. Instance of this holds a cryptographic key pair and a
 * certificate. <b>Note that this shall be used only for testing purposes as there are self-signed certificates
 * generated only.</b>
 */
public final class KeyPairAndCertificate {
    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final X509Certificate certificate;

    private KeyPairAndCertificate(PrivateKey privateKey, PublicKey publicKey, X509Certificate certificate) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.certificate = certificate;
    }

    /**
     * Generates a new key pair (RSA, 2048 bits) and a self-signed certificate for it (SHA1withRSA). The certificate
     * will use a distinguished name specified by {@code principal} and will be valid for 1 year.
     *
     * @param principal to be used in certificate subject/issuer
     * @return generated key pair
     * @throws GeneralSecurityException if there was an error during creating KeyPairGenerator or generating certificate
     */
    public static KeyPairAndCertificate generateSelfSigned(String principal) throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        Date from = new Date();
        Date to = new Date(from.getTime() + 365L * 24L * 60L * 60L * 1000L);
        BigInteger serialNumber = new BigInteger(64, new SecureRandom());
        X500Principal owner = new X500Principal(principal);

        X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();
        certificateGenerator.setIssuerDN(owner);
        certificateGenerator.setSubjectDN(owner);
        certificateGenerator.setNotBefore(from);
        certificateGenerator.setNotAfter(to);
        certificateGenerator.setSerialNumber(serialNumber);
        certificateGenerator.setPublicKey(keyPair.getPublic());
        certificateGenerator.setSignatureAlgorithm("SHA1withRSA");
        X509Certificate certificate = certificateGenerator.generate(keyPair.getPrivate());

        return new KeyPairAndCertificate(keyPair.getPrivate(), keyPair.getPublic(), certificate);
    }

    /**
     * Creates a new keystore that will contain a single entry with given {@code entryAlias} and {@code entryPassword}.
     * The entry will contain the private key and the certificate.
     *
     * @param entryAlias    alias for certificate/key entry in the the keystore
     * @param entryPassword password for the keystore
     * @param keystoreType  one of supported types of the keystore
     * @return generated keystore
     * @throws GeneralSecurityException error during creation, ie. unsupported type of keystore
     * @throws IOException              IO error during creation
     */
    public KeyStore toKeyStore(String entryAlias, char[] entryPassword, String keystoreType) throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance(keystoreType);
        keyStore.load(null, null);
        keyStore.setKeyEntry(entryAlias, privateKey, entryPassword, new Certificate[]{certificate});
        return keyStore;
    }

    /**
     * Creates a new truststore that will contain single entry of given certificate with alias specified in {@code
     * entryAlias} and encrypted by password {@code entryPassword}.
     *
     * @param entryAlias   alias for the certificate entry in the truststore
     * @param certificate  certificate that shall be added in the truststore
     * @param keystoreType one of supported types of the truststore
     * @return generated truststore
     * @throws GeneralSecurityException error during creation, ie. unsupported type of truststore
     * @throws IOException              IO error during creation
     */
    public static KeyStore toTrustStore(String entryAlias, Certificate certificate, String keystoreType) throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance(keystoreType);
        keyStore.load(null, null);
        keyStore.setCertificateEntry(entryAlias, certificate);
        return keyStore;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }
}

package com.wesbunton.projects.mycertificates;

import android.annotation.SuppressLint;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * This class is used to bypass the SSL verification of any HTTPS URL.
 * Because the specific inspection-only use of this application, the
 * security concerns surrounding this implementation can be acceptable.
*/
public class BypassSSLVerification {

    private HostnameVerifier defaultVerifier;
    private SSLSocketFactory defaultSocketFactory;

    public static void main(String[] args) {
        //Access HTTPS URL and do something
    }
    //Method used for bypassing SSL verification
    void disableSSLVerification() {

        // Save off the secure hostname verifier and socket factory
        defaultVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
        defaultSocketFactory = HttpsURLConnection.getDefaultSSLSocketFactory();

        TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            @SuppressLint("TrustAllX509TrustManager")
            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }

            @SuppressLint("TrustAllX509TrustManager")
            public void checkServerTrusted(X509Certificate[] certs, String authType) {
            }

        } };

        SSLContext sc = null;
        try {
            sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
        } catch (KeyManagementException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        assert sc != null;
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

        HostnameVerifier allHostsValid = new HostnameVerifier() {
            @SuppressLint("BadHostnameVerifier")
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };
        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
    }

    void enabledSSLVerification() {
        HttpsURLConnection.setDefaultHostnameVerifier(defaultVerifier);
        HttpsURLConnection.setDefaultSSLSocketFactory(defaultSocketFactory);
    }
}

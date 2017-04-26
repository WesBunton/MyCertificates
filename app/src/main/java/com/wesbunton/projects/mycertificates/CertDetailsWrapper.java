/****************************************************************************************
 * Author: Wesley Bunton
 * Date: November 2016
 *
 * Desc: This class will aid in wrapping up the certificate details so they can be viewed
 *          by the user.
 **************************************************************************************/
package com.wesbunton.projects.mycertificates;

import java.io.Serializable;
import java.security.cert.X509Certificate;

public class CertDetailsWrapper implements Serializable {

    private static String LOGTAG = CertDetailsWrapper.class.getSimpleName();

    // used for TLS inspection toggle
    private boolean tlsInspection;

    // chain length
    private int chainLength = 1;

    // user Cert
    private String alias;
    private X509Certificate userCert;

    // Intermediary Cert
    private X509Certificate intermediaryCert;

    // CA Cert
    private X509Certificate caCert;

    public CertDetailsWrapper() {
        // Intentionally left blank.
    }

    void setTlsInspection(boolean tlsInspection) { this.tlsInspection = tlsInspection; }

    void setChainLength(int chainLength) {
        this.chainLength = chainLength;
    }

    void setAlias(String alias) {
        this.alias = alias;
    }

    void setUserCert(X509Certificate userCert) {
        this.userCert = userCert;
    }

    void setIntermediaryCert(X509Certificate intermediaryCert) {
        this.intermediaryCert = intermediaryCert;
    }

    void setCaCert(X509Certificate caCert) {
        this.caCert = caCert;
    }

    boolean isTlsInspection() { return tlsInspection; }

    int getChainLength() {
        return chainLength;
    }

    String getAlias() {
        return alias;
    }

    X509Certificate getUserCert() {
        return userCert;
    }

    X509Certificate getIntermediaryCert() {
        return intermediaryCert;
    }

    X509Certificate getCaCert() {
        return caCert;
    }
}

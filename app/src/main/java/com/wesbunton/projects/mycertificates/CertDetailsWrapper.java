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

    public void setChainLength(int chainLength) {
        this.chainLength = chainLength;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public void setUserCert(X509Certificate userCert) {
        this.userCert = userCert;
    }

    public void setIntermediaryCert(X509Certificate intermediaryCert) {
        this.intermediaryCert = intermediaryCert;
    }

    public void setCaCert(X509Certificate caCert) {
        this.caCert = caCert;
    }

    public int getChainLength() {
        return chainLength;
    }

    public String getAlias() {
        return alias;
    }

    public X509Certificate getUserCert() {
        return userCert;
    }

    public X509Certificate getIntermediaryCert() {
        return intermediaryCert;
    }

    public X509Certificate getCaCert() {
        return caCert;
    }
}

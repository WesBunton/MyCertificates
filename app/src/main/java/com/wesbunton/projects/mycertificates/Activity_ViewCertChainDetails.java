package com.wesbunton.projects.mycertificates;

import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentManager;
import android.support.v4.app.FragmentPagerAdapter;
import android.support.v4.view.ViewPager;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.x500.RDN;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x500.style.BCStyle;
import org.spongycastle.asn1.x500.style.IETFUtils;
import org.spongycastle.cert.jcajce.JcaX509CertificateHolder;
import org.spongycastle.jce.PrincipalUtil;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Locale;

/**
 * Author: Wesley Bunton
 * Date: December 2016
 * Description: This class contains a tabbed activity for displaying certificate
 *      information. The fragments contain a list of certificate information
 *      fields, and a fragment will be created for every certificate that is
 *      in the cert chain returned from the Android KeyChain.
 */
public class Activity_ViewCertChainDetails extends AppCompatActivity {

    private CertDetailsWrapper certDetailsWrapper = null;

    /**
     * The {@link android.support.v4.view.PagerAdapter} that will provide
     * fragments for each of the sections. We use a
     * {@link FragmentPagerAdapter} derivative, which will keep every
     * loaded fragment in memory. If this becomes too memory intensive, it
     * may be best to switch to a
     * {@link android.support.v4.app.FragmentStatePagerAdapter}.
     */
    private SectionsPagerAdapter mSectionsPagerAdapter;

    /**
     * The {@link ViewPager} that will host the section contents.
     */
    private ViewPager mViewPager;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.view_cert_chain_details);

        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        // Get the cert details to check how many certs we have
        certDetailsWrapper = (CertDetailsWrapper) getIntent().getSerializableExtra("certDetailsWrapper");

        // Create the adapter that will return a fragment for each of the three
        // primary sections of the activity.
        mSectionsPagerAdapter = new SectionsPagerAdapter(getSupportFragmentManager(), certDetailsWrapper.getChainLength());

        // Set up the ViewPager with the sections adapter.
        mViewPager = (ViewPager) findViewById(R.id.container);
        mViewPager.setAdapter(mSectionsPagerAdapter);

    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        // Do not need the 3-dot menu on this activity
        //getMenuInflater().inflate(R.menu.menu_activity_view_cert_chain_details, menu);
        return true;
    }

    /**
     * A placeholder fragment containing a simple view.
     */
    public static class PlaceholderFragment extends Fragment {
        /**
         * The fragment argument representing the section number for this
         * fragment.
         */
        private static final String ARG_SECTION_NUMBER = "section_number";

        private static final String LOGTAG = Activity_ViewCertChainDetails.class.getSimpleName();

        public PlaceholderFragment() {
        }

        /**
         * Returns a new instance of this fragment for the given section
         * number.
         */
        public static PlaceholderFragment newInstance(int sectionNumber, Serializable certDetails) {
            PlaceholderFragment fragment = new PlaceholderFragment();
            Bundle args = new Bundle();
            args.putInt(ARG_SECTION_NUMBER, sectionNumber);
            // cert details are in here so we can create a fragment for each cert in chain
            args.putSerializable("certDetails", certDetails);
            fragment.setArguments(args);
            return fragment;
        }

        @Override
        public View onCreateView(LayoutInflater inflater, ViewGroup container,
                                 Bundle savedInstanceState) {
            View rootView = inflater.inflate(R.layout.fragment_activity_view_cert_chain_details, container, false);

            // Retrieve the certificate details to populate the data fields with
            CertDetailsWrapper certDetailsWrapper = (CertDetailsWrapper) getArguments().getSerializable("certDetails");

            // Section label
            TextView textSectionLabel = (TextView) rootView.findViewById(R.id.section_label);
            assert certDetailsWrapper != null;
            textSectionLabel.setText(getString(R.string.section_format,
                    getArguments().getInt(ARG_SECTION_NUMBER), certDetailsWrapper.getChainLength()));

            // Build the cert chain object
            X509Certificate[] chain;
            chain = new X509Certificate[certDetailsWrapper.getChainLength()];
            chain[0] = certDetailsWrapper.getUserCert();
            if (certDetailsWrapper.getIntermediaryCert() != null && certDetailsWrapper.getChainLength() > 2) {
                chain[certDetailsWrapper.getChainLength() - 2] = certDetailsWrapper.getIntermediaryCert();
                chain[certDetailsWrapper.getChainLength() - 1] = certDetailsWrapper.getCaCert();
            } else //noinspection StatementWithEmptyBody
                if (certDetailsWrapper.getCaCert() != null) {
                chain[certDetailsWrapper.getChainLength() - 1] = certDetailsWrapper.getCaCert();
            } else {
                // No additional certs in cert chain...
            }

            // Calculate the fields with the proper certificate data based on which fragment we're on
            switch (getArguments().getInt(ARG_SECTION_NUMBER)) {
                case 1:     // User or device certificate
                    X509Certificate userCert = certDetailsWrapper.getUserCert();

                    // Initiate field population
                    populate(userCert, certDetailsWrapper.getAlias(), rootView, certDetailsWrapper.isTlsInspection(), certDetailsWrapper.isSslVerificationPassed());

                    // Use the cert chain to calculate validity
                    verifiedBy(chain, (getArguments().getInt(ARG_SECTION_NUMBER) - 1), rootView);
                    break;
                case 2: // Intermediary CA or root CA Cert

                    if (certDetailsWrapper.getIntermediaryCert() != null) {
                        populate(certDetailsWrapper.getIntermediaryCert(), certDetailsWrapper.getAlias(), rootView, certDetailsWrapper.isTlsInspection(), certDetailsWrapper.isSslVerificationPassed());
                    } else {
                        populate(certDetailsWrapper.getCaCert(), certDetailsWrapper.getAlias(), rootView, certDetailsWrapper.isTlsInspection(), certDetailsWrapper.isSslVerificationPassed());
                    }

                    // User the chain length to determine which certificate should be used for field population
                    X509Certificate secondCert = null;
                    if (certDetailsWrapper.getChainLength() > 2) {  // we have an intermediary certificate
                        secondCert = certDetailsWrapper.getIntermediaryCert();
                    } else if (certDetailsWrapper.getChainLength() == 2) {      // single CA certificate
                        secondCert = certDetailsWrapper.getCaCert();
                    }

                    // Initiate field population
                    populate(secondCert, certDetailsWrapper.getAlias(), rootView, certDetailsWrapper.isTlsInspection(), certDetailsWrapper.isSslVerificationPassed());

                    // Use the cert chain to calculate validity
                    verifiedBy(chain, (getArguments().getInt(ARG_SECTION_NUMBER) - 1), rootView);
                    break;

                case 3:
                    X509Certificate caCert;
                    if (certDetailsWrapper.getChainLength() > 2) {      // root CA is present in chain
                        caCert = certDetailsWrapper.getCaCert();

                        // Initiate field population
                        populate(caCert, certDetailsWrapper.getAlias(), rootView, certDetailsWrapper.isTlsInspection(), certDetailsWrapper.isSslVerificationPassed());

                        // Use the cert chain to calculate validity
                        verifiedBy(chain, (getArguments().getInt(ARG_SECTION_NUMBER) - 1), rootView);
                    }

                    break;
                default:    // Although this case shouldn't be possible, it should result in all blank fields
                    break;
            }

            return rootView;
        }

        /***
         * Populates the 'verified by:' field within the certificate details activity.
         * The certificate chain must be passed in along with an index noting which chain
         * object is under consideration for verification. The view is necessary for populating
         * data field.
         *
         * Even in the instances where a certificate fails to be verified, this method will
         * populate the 'verified by' field with an appropriate error message informing the
         * user that no verifier could be found.
         * @param chain     X509Certificate[] array containing certificate chain from KeyChain.
         * @param index     Int to note which object in chain is being verified.
         * @param view      View required to update the 'VerifiedBy' edit text.
         */
        private void verifiedBy(X509Certificate[] chain, int index, View view) {
            // Link to UI fields
            TextView textViewVerifiedBy = (TextView) view.findViewById(R.id.verifiedBy);

            // Calculate the validity
            // "Verified by: getCommonName of validator"...
            try {
                if ((index + 1) < chain.length) {    // if there's a CA cert above in the chain
                    try {
                        // verify using the next cert up in the chain
                        chain[index].verify(chain[index+1].getPublicKey());
                        // if successful, display the CN of the next cert up
                        X500Name name = new JcaX509CertificateHolder(chain[index+1]).getSubject();
                        RDN rawCN = name.getRDNs(BCStyle.CN)[0];
                        String cn = IETFUtils.valueToString(rawCN.getFirst().getValue());
                        textViewVerifiedBy.setText(cn);
                    } catch (Exception e) {     // CA cert fails signature check
                        Log.e(LOGTAG, "Exception: " + e);
                        textViewVerifiedBy.setText(R.string.Cert_Verify_Error);
                    }
                } else if (isSelfSigned(chain[index])) {   // self-signed cert
                    X500Name name = new JcaX509CertificateHolder(chain[index]).getSubject();
                    RDN rawCN = name.getRDNs(BCStyle.CN)[0];
                    String cn = IETFUtils.valueToString(rawCN.getFirst().getValue());
                    String commonName = cn + getString(R.string.cn_self_signed_suffix);
                    textViewVerifiedBy.setText(commonName);
                } else {    // No valid issuer found
                    textViewVerifiedBy.setText(R.string.no_valid_issuer_error_msg);
                }
            } catch (Exception e) {     // Error occurs while checking validity
                Log.e(LOGTAG, "Exception: " + e);
                Log.e(LOGTAG, chain[index].getSubjectDN().getName() + " - Error when attempting to validate certificate.");
                textViewVerifiedBy.setText(R.string.Cert_Verify_Error);
            }
        }

        /**
         * Populates the majority of the data fields in the view cert details activity.
         * The alias parameter is only used to display as a reminder to the user which
         * certificate they selected from the KeyChain store.
         *
         * @param certificate   certificate to parse data from.
         * @param alias         alias from KeyChain to populate the 'alias' field with.
         * @param view          View required to update the views within the activity.
         */
        private void populate(X509Certificate certificate, String alias, View view, Boolean isTlsInspection, Boolean sslVerificationPassed) {

            // UI field linking
            TextView textViewAlias = (TextView) view.findViewById(R.id.alias);
            TextView textViewToCommon = (TextView) view.findViewById(R.id.to_common);
            TextView textViewToOrg = (TextView) view.findViewById(R.id.to_org);
            TextView textViewToOrgUnit = (TextView) view.findViewById(R.id.to_org_unit);
            TextView textViewByCommon = (TextView) view.findViewById(R.id.by_common);
            TextView textViewByOrg = (TextView) view.findViewById(R.id.by_org);
            TextView textViewByOrgUnit = (TextView) view.findViewById(R.id.by_org_unit);
            TextView textViewKeyAlg = (TextView) view.findViewById(R.id.key_alg);
            TextView textViewKeySize = (TextView) view.findViewById(R.id.keySize);
            TextView textViewPubModulus = (TextView) view.findViewById(R.id.pubModulus);
            TextView textViewPubExponent = (TextView) view.findViewById(R.id.pubExponent);
            TextView textViewSHA256Fingerprint = (TextView) view.findViewById(R.id.sha256Fingerprint);
            TextView textViewSHA1Fingerprint = (TextView) view.findViewById(R.id.sha1Fingerprint);
            TextView textViewIssuedOn = (TextView) view.findViewById(R.id.issuedOn);
            TextView textViewExpiresOn = (TextView) view.findViewById(R.id.expiresOn);
            TextView textViewSubject = (TextView) view.findViewById(R.id.subject);
            TextView textViewIssuerSubject = (TextView) view.findViewById(R.id.issuerSubject);
            TextView textViewSerialNumber = (TextView) view.findViewById(R.id.serialNumber);
            TextView textViewX509Version = (TextView) view.findViewById(R.id.x509Version);
            TextView textViewKeyUsage = (TextView) view.findViewById(R.id.keyUsage);
            TextView textViewSigAlg = (TextView) view.findViewById(R.id.sigAlg);
            TextView textViewSignature = (TextView) view.findViewById(R.id.signature);

            // Nested layout for consolidated fields that are specific to RSA keys
            //RelativeLayout rsaDetailsLayout = (RelativeLayout) view.findViewById(R.id.RSA_Details);

            // Variables for calculating RSA key info
            RSAPublicKey rsaPublicKey;
            BigInteger pubModulus;
            BigInteger exponent;

            int pubKeySize = 0;
            byte[] signature = certificate.getSignature();

            // These calculations differ if key is RSA/EC
            if (certificate.getPublicKey().getAlgorithm().matches("RSA")) {
                // cast the public key
                rsaPublicKey = (RSAPublicKey) certificate.getPublicKey();
                pubModulus = rsaPublicKey.getModulus();
                exponent = rsaPublicKey.getPublicExponent();
                pubKeySize = rsaPublicKey.getModulus().bitLength();

                // Because the modulus is usually large, we're only displaying a subset of the string - the first 30 characters or total length, which ever is less.
                String pubMod = pubModulus.toString().substring(0, Math.min(pubModulus.toString().length(), 30)) + "...";
                textViewPubModulus.setText(pubMod);
                String exponentStr = String.format(Locale.US, "%d", exponent);
                textViewPubExponent.setText(exponentStr);
                textViewKeyAlg.setText(certificate.getPublicKey().getAlgorithm());
            } else if (certificate.getPublicKey().getAlgorithm().matches(getString(R.string.EC))) {
                // Hide the fields where we've been populating RSA public key data
                //rsaDetailsLayout.setVisibility(View.GONE);

                textViewKeyAlg.setText(R.string.elliptic_curve);
                ECPublicKey ecPublicKey = (ECPublicKey) certificate.getPublicKey();
                pubKeySize = ecPublicKey.getParams().getCurve().getField().getFieldSize();
            }

            // If this is a TLS inspection, attempt to validate certificate
            if (isTlsInspection) {
                boolean isExpired = false;
                try {
                    TextView textView_aliasHeader = (TextView) view.findViewById(R.id.alias_header);
                    textView_aliasHeader.setText(R.string.alias_header_tls_inspection);
                    certificate.checkValidity();
                    textViewAlias.setText(R.string.cert_valid);
                } catch (CertificateExpiredException e) {
                    isExpired = true;
                    textViewAlias.setText(R.string.cert_expired);
                } catch (CertificateNotYetValidException e) {
                    textViewAlias.setText(R.string.cert_invalid);
                }
                // If the SSL connection wasn't trusted, inform
                // the user that the certificate is invalid,
                // unless we already have discovered that the cert
                // is expired.
                if (!sslVerificationPassed && !isExpired) {
                    textViewAlias.setText(R.string.cert_not_trusted);
                }
            } else {
                textViewAlias.setText(alias);
            }
            textViewKeySize.setText(String.valueOf(pubKeySize));
            textViewIssuedOn.setText(certificate.getNotBefore().toString());
            textViewExpiresOn.setText(certificate.getNotAfter().toString());
            // Serial number is in base 16, with colons inserted at every two digits, and converted to uppercase.
            textViewSerialNumber.setText(certificate.getSerialNumber().toString(16).replaceAll("(?<=..)(..)", ":$1").toUpperCase(Locale.US));
            textViewX509Version.setText(String.valueOf(certificate.getVersion()));
            textViewSigAlg.setText(certificate.getSigAlgName());
            textViewSignature.setText(String.valueOf(new BigInteger(signature).toString(16)));

            // Calculate the key fingerprints
            try {
                textViewSHA256Fingerprint.setText(getThumbPrint(certificate, "SHA-256"));
                textViewSHA1Fingerprint.setText(getThumbPrint(certificate, "SHA-1"));
            } catch (CertificateEncodingException | NoSuchAlgorithmException e) {
                e.printStackTrace();
                textViewSHA256Fingerprint.setText(R.string.fingerprint_calc_error);
                textViewSHA1Fingerprint.setText(R.string.fingerprint_calc_error);
            }

            // Display the distinguished names
            try {
                textViewSubject.setText(String.valueOf(PrincipalUtil.getSubjectX509Principal(certificate)));
                textViewIssuerSubject.setText(String.valueOf(PrincipalUtil.getIssuerX509Principal(certificate)));
            } catch (CertificateEncodingException e) {
                Log.e(LOGTAG, "Certificate Encoding Exception: " + e);
            }

            // Display the Subject information
            String toCommon = parseSubjectName(certificate, BCStyle.CN, false);
            String toOrg = parseSubjectName(certificate, BCStyle.O, false);
            String toOrgUnit = parseSubjectName(certificate, BCStyle.OU, false);
            String byCommon = parseSubjectName(certificate, BCStyle.CN, true);
            String byOrg = parseSubjectName(certificate, BCStyle.O, true);
            String byOrgUnit = parseSubjectName(certificate, BCStyle.OU, true);

            if (toCommon != null) {
                if (toCommon.contains(",")) {
                    toCommon = toCommon.substring(0, toCommon.indexOf(','));
                }
            }
            if (toOrg != null) {
                if (toOrg.contains(",")) {
                    toOrg = toOrg.substring(0, toOrg.indexOf(','));
                }
            }
            if (toOrgUnit != null) {
                if (toOrgUnit.contains(",")) {
                    toOrgUnit = toOrgUnit.substring(0, toOrgUnit.indexOf(','));
                }
            }
            if (byCommon != null) {
                if (byCommon.contains(",")) {
                    byCommon = byCommon.substring(0, byCommon.indexOf(','));
                }
            }
            if (byOrg != null) {
                if (byOrg.contains(",")) {
                    byOrg = byOrg.substring(0, byOrg.indexOf(','));
                }
            }
            if (byOrgUnit != null) {
                if (byOrgUnit.contains(",")) {
                    byOrgUnit = byOrgUnit.substring(0, byOrgUnit.indexOf(','));
                }
            }

            textViewToCommon.setText(toCommon);
            textViewToOrg.setText(toOrg);
            textViewToOrgUnit.setText(toOrgUnit);
            textViewByCommon.setText(byCommon);
            textViewByOrg.setText(byOrg);
            textViewByOrgUnit.setText(byOrgUnit);

            // Extract the key usage
            /*
            * KeyUsage::= BIT STRING { digitalSignature (0), nonRepudiation (1),
            * keyEncipherment (2), dataEncipherment (3), keyAgreement (4),
             * keyCertSign (5), cRLSign (6), encipherOnly (7), decipherOnly (8) }
            */
            boolean[] keyUsageFlags = certificate.getKeyUsage();
            String keyUsage = null;

            if (keyUsageFlags != null) {
                if (keyUsageFlags[0]) {
                    keyUsage = null + "Digital Signature\n";
                }
                if (keyUsageFlags[1]) {
                    keyUsage = keyUsage + "Non Repudiation\n";
                }
                if (keyUsageFlags[2]) {
                    keyUsage = keyUsage + "Key Encipherment\n";
                }
                if (keyUsageFlags[3]) {
                    keyUsage = keyUsage + "Data Encipherment\n";
                }
                if (keyUsageFlags[4]) {
                    keyUsage = keyUsage + "Key Agreement\n";
                }
                if (keyUsageFlags[5]) {
                    keyUsage = keyUsage + "Key Cert Sign\n";
                }
                if (keyUsageFlags[6]) {
                    keyUsage = keyUsage + "CRL Sign\n";
                }
                if (keyUsageFlags[7]) {
                    keyUsage = keyUsage + "Encipher Only\n";
                }
                if (keyUsageFlags[8]) {
                    keyUsage = keyUsage + "Decipher Only\n";
                }

                if (keyUsage != null) {
                    keyUsage = keyUsage.replace("null", "");    // Remove the word 'null' from string
                    keyUsage = keyUsage.trim();                 // Remove excess new lines
                    textViewKeyUsage.setText(keyUsage);
                }
            }
        }

        /**
         * This method returns a string that represents a parsed X509Certificate subject based
         * on the object identifier parameter.
         * @param cert      X509Certificate to parse.
         * @param objectIdentifier  Identifier to use when parsing the subject, (i.e. BCStyle.CN)
         * @return      String that contains subject parameter or null in the event of error.
         */
        private String parseSubjectName(X509Certificate cert, ASN1ObjectIdentifier objectIdentifier, boolean getIssuerInfo) {
            String retString = null;

            if (!getIssuerInfo) {
                try {
                    X500Name name = new JcaX509CertificateHolder(cert).getSubject();
                    if (name.getRDNs(objectIdentifier).length >= 1) {
                        RDN rawCN = name.getRDNs(objectIdentifier)[0];
                        retString = IETFUtils.valueToString(rawCN.getFirst().getValue());
                    }
                } catch (CertificateEncodingException e) {
                    e.printStackTrace();
                }
            } else {
                try {
                    String issuerSubject = String.valueOf(PrincipalUtil.getIssuerX509Principal(cert));

                    // Parse the X500 Principal
                    if (objectIdentifier == BCStyle.CN && issuerSubject.contains("CN=")) {
                        retString = issuerSubject.substring(issuerSubject.indexOf("CN="));
                    } else if (objectIdentifier == BCStyle.O && issuerSubject.contains("O=")) {
                        retString = issuerSubject.substring(issuerSubject.indexOf("O="));
                    } else if (objectIdentifier == BCStyle.OU && issuerSubject.contains("OU=")) {
                        retString = issuerSubject.substring(issuerSubject.indexOf("OU="));
                    }
                } catch (CertificateEncodingException e) {
                    e.printStackTrace();
                }
            }

            return retString;
        }

        /**
         * Returns a boolean value indicating if the certificate passed in is
         * self-signed.
         *
         * @param cert  Certificate to evaluate.
         * @return      True indicates the certificate is self-signed, false if not.
         * @throws CertificateException
         * @throws NoSuchAlgorithmException
         * @throws NoSuchProviderException
         */
        public boolean isSelfSigned(X509Certificate cert) throws CertificateException,
                NoSuchAlgorithmException, NoSuchProviderException {
            try {
                // Try to verify certificate signature with its own public key
                PublicKey key = cert.getPublicKey();
                cert.verify(key);
                return true;
            } catch (SignatureException sigEx) {
                // Invalid signature --> not self-signed
                return false;
            } catch (InvalidKeyException keyEx) {
                // Invalid key --> not self-signed
                return false;
            }
        }

        /**
         * Returns a string value of the certificate thumbprint in hex format.
         * @param cert  Certificate to calculate thumbprint of.
         * @return      String value of certificate thumbprint in hex.
         * @throws NoSuchAlgorithmException
         * @throws CertificateEncodingException
         */
        public static String getThumbPrint(X509Certificate cert, String algorithm)
                throws NoSuchAlgorithmException, CertificateEncodingException {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            byte[] der = cert.getEncoded();
            md.update(der);
            byte[] digest = md.digest();
            String hex = hexify(digest);

            // Add colons to the hex string
            return hex.replaceAll("(?<=..)(..)", ":$1").toUpperCase(Locale.US);
        }

        /**
         * Converts the input byte array to hex format and returns
         * the string value of the new format.
         * @param bytes     Byte array to convert to hex.
         * @return          String of hex conversion.
         */
        public static String hexify (byte bytes[]) {

            char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7',
                    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

            StringBuilder buf = new StringBuilder(bytes.length * 2);

            for (byte aByte : bytes) {
                buf.append(hexDigits[(aByte & 0xf0) >> 4]);
                buf.append(hexDigits[aByte & 0x0f]);
            }

            return buf.toString();
        }
    }

    /**
     * A {@link FragmentPagerAdapter} that returns a fragment corresponding to
     * one of the sections/tabs/pages.
     */
    public class SectionsPagerAdapter extends FragmentPagerAdapter {

        private int pageCount = 1;

        /**
         * This adapter sets the number of pages to generate for the viewing
         * of certificate details. The length of the certificate chain is
         * used here to set the number of pages.
         * @param fm    Fragment manager used for the tabbed Android activity.
         * @param certChainLength   Integer value indicating the number of objects
         *                          in the certificate chain.
         */
        SectionsPagerAdapter(FragmentManager fm, int certChainLength) {
            super(fm);
            this.pageCount = certChainLength;
        }

        @Override
        public Fragment getItem(int position) {
            // getItem is called to instantiate the fragment for the given page.
            // Return a PlaceholderFragment (defined as a static inner class below).
            return PlaceholderFragment.newInstance(position + 1, certDetailsWrapper);
        }

        @Override
        public int getCount() {
            // Show a page per cert in chain.
            return pageCount;
        }

        @Override
        public CharSequence getPageTitle(int position) {
            switch (position) {
                case 0:
                    return "SECTION 1";
                case 1:
                    return "SECTION 2";
                case 2:
                    return "SECTION 3";
            }
            return null;
        }
    }
}

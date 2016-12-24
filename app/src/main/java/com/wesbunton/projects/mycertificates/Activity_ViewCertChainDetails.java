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
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.RelativeLayout;
import android.widget.TextView;

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
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 * CLASSIFICATION: UNCLASSIFIED
 * Author: Wesley Bunton
 * Date: December 2016
 * Description: This class contains a tabbed activity for displaying certificate
 *      information. The fragments contain a list of certificate information
 *      fields, and a fragment will be created for every certificate that is
 *      in the cert chain returned from the Android KeyChain.
 */
public class Activity_ViewCertChainDetails extends AppCompatActivity {

    final String LOGTAG = Activity_ViewCertChainDetails.class.getSimpleName();

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

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_about) {
            return true;
        }

        return super.onOptionsItemSelected(item);
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
            textSectionLabel.setText(getString(R.string.section_format, getArguments().getInt(ARG_SECTION_NUMBER), certDetailsWrapper.getChainLength()));

            // Build the cert chain object
            X509Certificate[] chain;
            chain = new X509Certificate[certDetailsWrapper.getChainLength()];
            chain[0] = certDetailsWrapper.getUserCert();
            if (certDetailsWrapper.getIntermediaryCert() != null && certDetailsWrapper.getChainLength() > 2) {
                chain[certDetailsWrapper.getChainLength() - 2] = certDetailsWrapper.getIntermediaryCert();
                chain[certDetailsWrapper.getChainLength() - 1] = certDetailsWrapper.getCaCert();
            } else if (certDetailsWrapper.getCaCert() != null) {
                chain[certDetailsWrapper.getChainLength() - 1] = certDetailsWrapper.getCaCert();
            } else {
                // No additional certs in cert chain...
            }

            // Calculate the fields with the proper certificate data based on which fragment we're on
            switch (getArguments().getInt(ARG_SECTION_NUMBER)) {
                case 1:     // User or device certificate
                    X509Certificate userCert = certDetailsWrapper.getUserCert();

                    // Initiate field population
                    populate(userCert, certDetailsWrapper.getAlias(), rootView);

                    // Use the cert chain to calculate validity
                    verifiedBy(chain, (getArguments().getInt(ARG_SECTION_NUMBER) - 1), rootView);
                    break;
                case 2: // Intermediary CA or root CA Cert

                    if (certDetailsWrapper.getIntermediaryCert() != null) {
                        populate(certDetailsWrapper.getIntermediaryCert(), certDetailsWrapper.getAlias(), rootView);
                    } else {
                        populate(certDetailsWrapper.getCaCert(), certDetailsWrapper.getAlias(), rootView);
                    }

                    // User the chain length to determine which certificate should be used for field population
                    X509Certificate secondCert = null;
                    if (certDetailsWrapper.getChainLength() > 2) {  // we have an intermediary certificate
                        secondCert = certDetailsWrapper.getIntermediaryCert();
                    } else if (certDetailsWrapper.getChainLength() == 2) {      // single CA certificate
                        secondCert = certDetailsWrapper.getCaCert();
                    }

                    // Initiate field population
                    populate(secondCert, certDetailsWrapper.getAlias(), rootView);

                    // Use the cert chain to calculate validity
                    verifiedBy(chain, (getArguments().getInt(ARG_SECTION_NUMBER) - 1), rootView);
                    break;

                case 3:
                    X509Certificate caCert = null;
                    if (certDetailsWrapper.getChainLength() > 2) {      // root CA is present in chain
                        caCert = certDetailsWrapper.getCaCert();

                        // Initiate field population
                        populate(caCert, certDetailsWrapper.getAlias(), rootView);

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
            EditText editText_VerifiedBy = (EditText) view.findViewById(R.id.editTxt_VerifiedBy);

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
                        editText_VerifiedBy.setText(cn);
                    } catch (Exception e) {     // CA cert fails signature check
                        Log.e(LOGTAG, "Exception: " + e);
                        editText_VerifiedBy.setText(R.string.Cert_Verify_Error);
                    }
                } else if (isSelfSigned(chain[index])) {   // self-signed cert
                    X500Name name = new JcaX509CertificateHolder(chain[index]).getSubject();
                    RDN rawCN = name.getRDNs(BCStyle.CN)[0];
                    String cn = IETFUtils.valueToString(rawCN.getFirst().getValue());
                    editText_VerifiedBy.setText(cn + "\t\t(Self-Signed)");
                } else {    // No valid issuer found
                    editText_VerifiedBy.setText("Cannot find valid issuer.");
                }
            } catch (Exception e) {     // Error occurs while checking validity
                Log.e(LOGTAG, "Exception: " + e);
                Log.e(LOGTAG, chain[index].getSubjectDN().getName() + " - Error when attempting to validate certificate.");
                editText_VerifiedBy.setText(R.string.Cert_Verify_Error);
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
        private void populate(X509Certificate certificate, String alias, View view) {

            // UI field linking
            EditText editText_Alias = (EditText) view.findViewById(R.id.editTxt_Alias);
            EditText editText_PubKeyAlg = (EditText) view.findViewById(R.id.editTxt_PubKey);
            EditText editText_PubKeySize = (EditText) view.findViewById(R.id.editTxt_PubKeySize);
            EditText editText_PubModulus = (EditText) view.findViewById(R.id.editTxt_PubModulus);
            EditText editText_PubExponent = (EditText) view.findViewById(R.id.editTxt_PubExponent);
            EditText editText_PubFP = (EditText) view.findViewById(R.id.editTxt_PublicFingerprint);
            EditText editText_NotBefore = (EditText) view.findViewById(R.id.editTxt_NotBefore);
            EditText editText_NotAfter = (EditText) view.findViewById(R.id.editTxt_NotAfter);
            EditText editText_SubDN = (EditText) view.findViewById(R.id.editTxt_SubDN);
            EditText editText_IssuerDN = (EditText) view.findViewById(R.id.editTxt_IssuerDN);
            EditText editText_Serial = (EditText) view.findViewById(R.id.editTxt_Serial);
            EditText editText_Version = (EditText) view.findViewById(R.id.editTxt_Version);
            EditText editText_Usage = (EditText) view.findViewById(R.id.editTxt_Usage);
            EditText editText_sigAlg = (EditText) view.findViewById(R.id.editTxt_SigAlg);
            EditText editText_sig = (EditText) view.findViewById(R.id.editTxt_Signature);

            // Nested layout for consolidated fields that are specific to RSA keys
            RelativeLayout rsaDetailsLayout = (RelativeLayout) view.findViewById(R.id.RSA_Details);

            // Variables for calculating RSA key info
            RSAPublicKey rsaPublicKey = null;
            BigInteger pubModulus = null;
            BigInteger exponent = null;

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
                editText_PubModulus.setText(pubModulus.toString().substring(0, Math.min(pubModulus.toString().length(), 30)) + "...");
                editText_PubExponent.setText(exponent.toString());
                editText_PubKeyAlg.setText(certificate.getPublicKey().getAlgorithm());
            } else if (certificate.getPublicKey().getAlgorithm().matches("EC")) {
                // Hide the fields where we've been populating RSA public key data
                rsaDetailsLayout.setVisibility(View.GONE);

                editText_PubKeyAlg.setText("Elliptic Curve");
                ECPublicKey ecPublicKey = (ECPublicKey) certificate.getPublicKey();
                pubKeySize = ecPublicKey.getParams().getCurve().getField().getFieldSize();
            }

            editText_Alias.setText(alias);
            editText_PubKeySize.setText(String.valueOf(pubKeySize));
            editText_NotBefore.setText(certificate.getNotBefore().toString());
            editText_NotAfter.setText(certificate.getNotAfter().toString());
            editText_Serial.setText(certificate.getSerialNumber().toString(16));
            editText_Version.setText(String.valueOf(certificate.getVersion()));
            editText_sigAlg.setText(certificate.getSigAlgName());
            editText_sig.setText(String.valueOf(new BigInteger(signature).toString(16)));

            // Calculate the key fingerprint
            try {
                editText_PubFP.setText(getThumbPrint(certificate));
            } catch (CertificateEncodingException | NoSuchAlgorithmException e) {
                e.printStackTrace();
                editText_PubFP.setText("Could not calculate fingerprint.");
            }

            // Display the distinguished names
            try {
                editText_SubDN.setText(String.valueOf(PrincipalUtil.getSubjectX509Principal(certificate)));
                editText_IssuerDN.setText(String.valueOf(PrincipalUtil.getIssuerX509Principal(certificate)));
            } catch (CertificateEncodingException e) {
                Log.e(LOGTAG, "Certificate Encoding Exception: " + e);
            }

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
                    keyUsage = keyUsage + "Digital Signature\n";
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
                    editText_Usage.setText(keyUsage);
                }
            }
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
        public static String getThumbPrint(X509Certificate cert)
                throws NoSuchAlgorithmException, CertificateEncodingException {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] der = cert.getEncoded();
            md.update(der);
            byte[] digest = md.digest();
            return hexify(digest);

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

            StringBuffer buf = new StringBuffer(bytes.length * 2);

            for (int i = 0; i < bytes.length; ++i) {
                buf.append(hexDigits[(bytes[i] & 0xf0) >> 4]);
                buf.append(hexDigits[bytes[i] & 0x0f]);
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
        public SectionsPagerAdapter(FragmentManager fm, int certChainLength) {
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

package com.wesbunton.projects.mycertificates;

import android.app.ProgressDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Bundle;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.security.KeyChainException;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.text.InputType;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import org.apache.commons.io.IOUtils;
import org.spongycastle.cert.X509CertificateHolder;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.net.ssl.HttpsURLConnection;

import uk.co.deanwild.materialshowcaseview.MaterialShowcaseSequence;
import uk.co.deanwild.materialshowcaseview.MaterialShowcaseView;
import uk.co.deanwild.materialshowcaseview.ShowcaseConfig;

/**
 * This is the class for the main activity of the My Certificates application.
 * This dialog will handle the main screen button(s) onClick behavior and the
 * menu options.
 */
public class MainActivity extends AppCompatActivity {

    private final String LOGTAG = MainActivity.class.getSimpleName();

    // Request code for selecting a file
    private final int CHOOSE_FILE_REQUEST_CODE = 1212;

    // This value is used to track whether or not the HTTPSURLConnection
    // class is able to validate the SSL connection certificate.
    private boolean sslVerificationPassed;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        // Show sequence of tips on first launch...
        showTipsSequence(100, isThisFirstLaunch());  // half a second delay (in milliseconds)

        // Set shared pref to indicate first launch is complete
        setAppLaunchedPref();

        // Inspect a certificate from the keychain
        Button btnListCerts = (Button) findViewById(R.id.btn_listCerts);
        btnListCerts.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // Prompt user to select certificate
                KeyChain.choosePrivateKeyAlias(MainActivity.this, new KeyChainAliasCallback() {
                    @Override
                    public void alias(String alias) {
                        // If user denies access to the selected certificate
                        if (alias == null) {
                            return;
                        }

                        // Pull data from KeyChain
                        java.security.cert.X509Certificate[] chain;
                        try {
                            chain = KeyChain.getCertificateChain(MainActivity.this, alias);
                        } catch (KeyChainException | InterruptedException e) {
                            e.printStackTrace();
                            MyCertificatesUtilities.showAlertDialog(MainActivity.this, getString(R.string.error),
                                    getString(R.string.error_msg_retrieve_store));
                            return;
                        }
                        passCertDetails(chain, false);
                    }
                }, new String[] {}, null, null, -1, null);
            }
        });

        // Inspect certificates from file
        Button btn_insectCertFromFile = (Button) findViewById(R.id.btn_inspectFromFile);
        btn_insectCertFromFile.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // Launch the file picker intent
                Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                intent.setType("*/*");
                startActivityForResult(intent, CHOOSE_FILE_REQUEST_CODE);
            }
        });

        // Inspect TLS Certificate
        Button btn_inspectTlsCert = (Button) findViewById(R.id.btn_InspectTLS);
        btn_inspectTlsCert.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // Prompt user for URL
                final EditText editText_url = new EditText(MainActivity.this);
                editText_url.setMaxLines(1);
                editText_url.setHint(R.string.url_hint);
                editText_url.setInputType(InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
                AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
                builder.setTitle(R.string.tls_title);
                builder.setMessage(R.string.tls_message);
                builder.setView(editText_url);
                builder.setNegativeButton(R.string.tls_cancel, null);
                builder.setPositiveButton(R.string.tls_check_cert, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        // Validate the input
                        boolean error = false;
                        String url = editText_url.getText().toString();
                        if (url.isEmpty()) {
                            MyCertificatesUtilities.showAlertDialog(MainActivity.this, getString(R.string.error),
                                    getString(R.string.tls_error_empty_url));
                            error = true;
                        } else if (!MyCertificatesUtilities.isValidUrl(url)) {
                            MyCertificatesUtilities.showAlertDialog(MainActivity.this, getString(R.string.error),
                                    getString(R.string.tls_error_invalid_url));
                            error = true;
                        }
                        if (url.contains("http://")) {
                            MyCertificatesUtilities.showAlertDialog(MainActivity.this, getString(R.string.error),
                                    getString(R.string.tls_error_http));
                            error = true;
                        }
                        if (!url.contains("https://")) {
                            url = "https://" + url;
                        }
                        if (!error) {
                            // Retrieve cert chain from validated URL
                            URL urlToCheck;
                            try {
                                urlToCheck = new URL(url);
                                new RetrieveTlsCertificate().execute(urlToCheck);
                            } catch (MalformedURLException e) {
                                e.printStackTrace();
                            }
                        }
                    }
                });
                builder.show();
            }
        });
    }

    /**
     * This AsyncTask handles the retrieval of the TLS certificates from the supplied URL.
     */
    class RetrieveTlsCertificate extends AsyncTask<URL, Void, Certificate[]> {

        ProgressDialog progressDialog;

        @Override
        protected void onPreExecute() {
            super.onPreExecute();
            // Disable screen orientation
            MainActivity.this.setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_NOSENSOR);
            // Show progress dialog
            progressDialog = new ProgressDialog(MainActivity.this);
            progressDialog.setCancelable(false);
            progressDialog.setMessage("Retrieving TLS certificate...");
            progressDialog.show();
        }

        @Override
        protected Certificate[] doInBackground(URL... params) {
            // Previously validated
            URL url = params[0];
            HttpsURLConnection connection;
            Certificate[] chain;
            try {
                // Connect to URL
                assert url != null;
                connection = (HttpsURLConnection) url.openConnection();
                connection.setConnectTimeout(3000); // 3 second timeout
                // Get the server certificate chain
                try {
                    // To fix 'Connection has not yet been established' error
                    StringWriter writer = new StringWriter();
                    IOUtils.copy(connection.getInputStream(), writer, Charset.defaultCharset());
                    // This data is not used, only pulled to open a data connection to web server
                    //noinspection ResultOfMethodCallIgnored
                    writer.toString();
                    sslVerificationPassed = true;
                    // Retrieve cert chain
                    chain = connection.getServerCertificates();
                } catch (IOException e) {
                    Log.d(LOGTAG, getString(R.string.log_bypassing_ssl_verification));
                    // This is used to prevent exceptions in the event the certs are not valid
                    BypassSSLVerification myBypass = new BypassSSLVerification();
                    myBypass.disableSSLVerification();
                    // Record that the cert is not trusted by the HTTPS class
                    sslVerificationPassed = false;
                    // Try again after enabling the SSL verification bypass
                    // Re-connect after bypassing SSL verification...
                    connection = (HttpsURLConnection) url.openConnection();
                    connection.setConnectTimeout(3000); // 3 second timeout
                    // To fix 'Connection has not yet been established' error
                    StringWriter writer = new StringWriter();
                    IOUtils.copy(connection.getInputStream(), writer, Charset.defaultCharset());
                    // This data is not used, only pulled to open a data connection to web server
                    //noinspection ResultOfMethodCallIgnored
                    writer.toString();
                    // Retrieve cert chain
                    chain = connection.getServerCertificates();
                    // Reinstate the SSL verification
                    myBypass.enabledSSLVerification();
                }
            } catch (IOException e) {
                e.printStackTrace();
                return null;
            }
            return chain;
        }

        @Override
        protected void onPostExecute(Certificate[] certificates) {
            super.onPostExecute(certificates);
            // Cancel the progress dialog
            if (progressDialog.isShowing()) {
                progressDialog.cancel();
            }

            // Check if the chain was retrieved or not
            if (certificates == null) {
                MyCertificatesUtilities.showAlertDialog(MainActivity.this, getString(R.string.error), getString(R.string.error_retrieve_cert));
            } else {
                passCertDetails(certificates, true);
            }
        }
    }

    void passCertDetails(Certificate[] chain, boolean isTlsInspection) {
        // Wrapper to store the data we unpack from KeyChain
        CertDetailsWrapper certDetailsWrapper = new CertDetailsWrapper();
        // Pack data into wrapper
        assert chain != null;
        certDetailsWrapper.setTlsInspection(isTlsInspection);
        certDetailsWrapper.setChainLength(chain.length);
        certDetailsWrapper.setUserCert((X509Certificate) chain[0]);

        // If TLS inspection is happening, track if the SSL connection was successful
        if (isTlsInspection) {
            certDetailsWrapper.setSslVerificationPassed(sslVerificationPassed);
        }

        // Get the last in the chain for the CA cert
        if (chain.length > 2) {     // if there's 3 or more certs total in chain
            certDetailsWrapper.setCaCert((X509Certificate) chain[(chain.length - 1)]);    // root CA is the top level certificate
            certDetailsWrapper.setIntermediaryCert((X509Certificate) chain[(chain.length - 2)]);  // intermediary is below the root
        } else if (chain.length == 2) {     // there's only a user and ca cert
            certDetailsWrapper.setCaCert((X509Certificate) chain[(chain.length - 1)]);    // root CA is the top level certificate
        } else //noinspection StatementWithEmptyBody
            if (chain.length == 1) {     // Chain consists of just user and CA cert
                // No cert chain exists...
            }

        // Start the View Certificate Chain Details activity
        Intent intent = new Intent(MainActivity.this, Activity_ViewCertChainDetails.class);
        Bundle bundle = new Bundle();
        bundle.putSerializable("certDetailsWrapper", certDetailsWrapper);
        intent.putExtras(bundle);
        intent.setClass(MainActivity.this, Activity_ViewCertChainDetails.class);
        startActivity(intent);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        // If we're done selecting a file to inspect
        if (requestCode == CHOOSE_FILE_REQUEST_CODE) {
            if (data != null) {
                // Parse the PEM data
                final Uri uri = data.getData();
                X509CertificateHolder certHolder;
                certHolder = MyCertificatesUtilities.parsePemFile(MainActivity.this, uri);
                if (certHolder == null) {
                    // Assume the file is a P12 certificate
                    processP12Certificate(MainActivity.this, uri);
                    return;
                }

                X509Certificate certToInspect = MyCertificatesUtilities.certConverter(certHolder);
                if (certToInspect == null) {
                    MyCertificatesUtilities.showAlertDialog(MainActivity.this, getString(R.string.certificate_error_title), getString(R.string.error_message_convert_pem_cert));
                    return;
                }

                // Pack up the certificate details to pass to the ViewDetails activity
                CertDetailsWrapper certDetailsWrapper = new CertDetailsWrapper();
                certDetailsWrapper.setAlias(getString(R.string.set_alias_cert_from_file));
                certDetailsWrapper.setCaCert(null);
                certDetailsWrapper.setChainLength(1);
                certDetailsWrapper.setIntermediaryCert(null);
                certDetailsWrapper.setUserCert(certToInspect);

                // Start the View Certificate Chain Details activity
                Intent intent = new Intent(MainActivity.this, Activity_ViewCertChainDetails.class);
                Bundle bundle = new Bundle();
                bundle.putSerializable("certDetailsWrapper", certDetailsWrapper);
                intent.putExtras(bundle);
                intent.setClass(MainActivity.this, Activity_ViewCertChainDetails.class);
                startActivity(intent);
            }
        }
    }

    private void processP12Certificate(final Context context, final Uri uri) {
        // This most likely means the user has selected a p12 certificate file.
        LayoutInflater inflater = getLayoutInflater();
        final View myView = inflater.inflate(R.layout.p12_password_dialog, (ViewGroup)this.findViewById(R.id.content_main), false);
        AlertDialog.Builder builder = new AlertDialog.Builder(context);
        builder.setCancelable(false);
        builder.setView(myView);
        final EditText providedPassword = (EditText) myView.findViewById(R.id.editTxt_p12Password);
        builder.setPositiveButton("OK", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                try {
                    KeyStore p12 = KeyStore.getInstance("pkcs12");
                    InputStream inputStream = context.getContentResolver().openInputStream(uri);
                    p12.load(inputStream, providedPassword.getText().toString().toCharArray());
                    Enumeration enumeration = p12.aliases();
                    X509Certificate certificateToInspect = null;
                    while (enumeration.hasMoreElements()) {
                        String alias = (String) enumeration.nextElement();
                        X509Certificate cert = (X509Certificate) p12.getCertificate(alias);
                        certificateToInspect = cert;
                        Principal subject = cert.getSubjectDN();
                        String subjectArray[] = subject.toString().split(",");
                        for (String s : subjectArray) {
                            String[] str = s.trim().split("=");
                            String key = str[0];
                            String value = str[1];
                            System.out.println(key + " - " + value);
                        }
                    }

                    if (certificateToInspect != null) {
                        // Pack up the certificate details to pass to the ViewDetails activity
                        CertDetailsWrapper certDetailsWrapper = new CertDetailsWrapper();
                        certDetailsWrapper.setAlias(getString(R.string.set_alias_cert_from_file));
                        certDetailsWrapper.setCaCert(null);
                        certDetailsWrapper.setChainLength(1);
                        certDetailsWrapper.setIntermediaryCert(null);
                        certDetailsWrapper.setUserCert(certificateToInspect);

                        // Start the View Certificate Chain Details activity
                        Intent intent = new Intent(MainActivity.this, Activity_ViewCertChainDetails.class);
                        Bundle bundle = new Bundle();
                        bundle.putSerializable("certDetailsWrapper", certDetailsWrapper);
                        intent.putExtras(bundle);
                        intent.setClass(MainActivity.this, Activity_ViewCertChainDetails.class);
                        startActivity(intent);
                    }
                } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | FileNotFoundException e) {
                    e.printStackTrace();
                    MyCertificatesUtilities.showAlertDialog(context, getString(R.string.error_text), getString(R.string.error_message_general_error));
                } catch (IOException e) {
                    e.printStackTrace();

                    // Wrong password entered
                    if (e.getMessage().contains(getString(R.string.bad_password_exception))) {
                        MyCertificatesUtilities.showAlertDialog(context, getString(R.string.wrong_password_error_title), getString(R.string.wrong_password_error_message));
                    } else {
                        MyCertificatesUtilities.showAlertDialog(context, getString(R.string.error_text), getString(R.string.error_message_general_error));
                    }
                }
            }
        });
        builder.setNegativeButton(R.string.cancel_text, new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                dialog.cancel();
            }
        });
        AlertDialog dialog = builder.create();
        // Launch virtual keyboard on showing of alert dialog
        //noinspection ConstantConditions
        dialog.getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_VISIBLE);
        dialog.show();
        providedPassword.requestFocus();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        if (id == R.id.action_about) {
            String version = "";
            try {
                // Retrieve the app version number
                PackageInfo packageInfo = getPackageManager().getPackageInfo(getPackageName(), 0);
                version = "Version " + packageInfo.versionName;
            } catch (PackageManager.NameNotFoundException e) {
                e.printStackTrace();
            }

            // Create the About dialog
            AlertDialog dialog = new AlertDialog.Builder(MainActivity.this)
                    .setCancelable(true)
                    .setView(R.layout.about_dialog)
                    .create();

            // Show the About dialog
            dialog.show();

            // Display the proper app version in dialog
            TextView txtVersion = (TextView) dialog.findViewById(R.id.appVersion);
            assert txtVersion != null;
            txtVersion.setText(version);

            return true;
        }

        // Show tips
        if (id == R.id.action_show_tips) {
            showTipsSequence(100, true);
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    /**
     * This method checks the shared preferences to see
     * if this is the first time the device user has
     * launched this app.
     * @return  True if first launch, false if not.
     */
    private boolean isThisFirstLaunch() {
        SharedPreferences myCertsSharedPref = getSharedPreferences(MyCertsConstants.MY_PREFS, MODE_PRIVATE);
        return myCertsSharedPref.getBoolean(MyCertsConstants.FIRST_LAUNCH, true);
    }

    /**
     * This method is used to configure the shared preferences
     * to indicate that the device user has launched this app
     * at least once. It takes no parameters and returns void.
     */
    private void setAppLaunchedPref() {
        SharedPreferences.Editor myCertsSharedPrefEditor = getSharedPreferences(MyCertsConstants.MY_PREFS, MODE_PRIVATE).edit();
        myCertsSharedPrefEditor.putBoolean(MyCertsConstants.FIRST_LAUNCH, false);
        myCertsSharedPrefEditor.apply();
    }

    /**
     * This method will display a tip on the screen when the app is
     * first launched.
     * @param withDelay     Delay in milliseconds for the tip to be shown.
     */
    private void showTipsSequence(int withDelay, boolean firstLaunch) {
        if (firstLaunch) {
            MaterialShowcaseSequence tipsSequence = new MaterialShowcaseSequence(this);
            ShowcaseConfig config = new ShowcaseConfig();
            config.setDelay(withDelay);

            MaterialShowcaseView lockScreenTip = new MaterialShowcaseView.Builder(this)
                    .setTarget(findViewById(R.id.btn_listCerts))
                    .withRectangleShape()
                    .setTitleText("Did you know?")
                    .setContentText(getString(R.string.tip_lock_screen))
                    .setDismissText("Okay!")
                    .build();
            MaterialShowcaseView issuerTip = new MaterialShowcaseView.Builder(this)
                    .setTarget(findViewById(R.id.btn_listCerts))
                    .withRectangleShape()
                    .setTitleText("Also...")
                    .setContentText(getString(R.string.tip_issuer_cert))
                    .setDismissText("Got It!")
                    .build();
            MaterialShowcaseView fileTip = new MaterialShowcaseView.Builder(this)
                    .setTarget(findViewById(R.id.btn_inspectFromFile))
                    .withRectangleShape()
                    .setTitleText("Or inspect a local file...")
                    .setContentText(getString(R.string.tip_file))
                    .setDismissText("Got It!")
                    .build();
            MaterialShowcaseView tlsTip = new MaterialShowcaseView.Builder(this)
                    .setTarget(findViewById(R.id.btn_InspectTLS))
                    .withRectangleShape()
                    .setTitleText("New feature!")
                    .setContentText(getString(R.string.tip_tls))
                    .setDismissText("Got It!")
                    .build();

            tipsSequence.setConfig(config);
            tipsSequence.addSequenceItem(lockScreenTip);
            tipsSequence.addSequenceItem(issuerTip);
            tipsSequence.addSequenceItem(fileTip);
            tipsSequence.addSequenceItem(tlsTip);
            tipsSequence.start();
        }
    }
}

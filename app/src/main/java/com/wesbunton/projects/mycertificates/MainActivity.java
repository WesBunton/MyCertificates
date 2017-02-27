package com.wesbunton.projects.mycertificates;

import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.security.KeyChainException;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import org.spongycastle.cert.X509CertificateHolder;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import uk.co.deanwild.materialshowcaseview.MaterialShowcaseSequence;
import uk.co.deanwild.materialshowcaseview.MaterialShowcaseView;
import uk.co.deanwild.materialshowcaseview.ShowcaseConfig;
import uk.co.deanwild.materialshowcaseview.target.ViewTarget;

/**
 * This is the class for the main activity of the My Certificates application.
 * This dialog will handle the main screen button(s) onClick behavior and the
 * menu options.
 */
public class MainActivity extends AppCompatActivity {

    private final String LOGTAG = MainActivity.class.getSimpleName();

    private final int CHOOSE_FILE_REQUEST_CODE = 1212;

    // String used to track if the tips should be launched
    private static final String SHOWCASE_ID = "tips sequence";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        // Show sequence of tips on first launch...
        showTipsSequence(100, isThisFirstLaunch());  // half a second delay (in milliseconds)

        Button btnListCerts = (Button) findViewById(R.id.btn_listCerts);
        btnListCerts.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // Prompt user to select certificate
                KeyChain.choosePrivateKeyAlias(MainActivity.this, new KeyChainAliasCallback() {
                    @Override
                    public void alias(String alias) {
                        Log.d(LOGTAG, "Thread: " + Thread.currentThread().getName());
                        Log.d(LOGTAG, "selected alias: " + alias);

                        // If user denies access to the selected certificate
                        if (alias == null) {
                            Log.i(LOGTAG, "Returned key alias is null");
                            return;
                        }

                        // Wrapper to store the data we unpack from KeyChain
                        CertDetailsWrapper certDetailsWrapper = new CertDetailsWrapper();
                        java.security.cert.X509Certificate[] chain = null;

                        // Pull data from KeyChain
                        try {
                            chain = KeyChain.getCertificateChain(MainActivity.this, alias);
                        } catch (KeyChainException | InterruptedException e) {
                            e.printStackTrace();
                        }

                        // Check if any KeyChain variables are empty
                        if (chain == null || chain.length == 0) {
                            alertBadAlias();    // Alert dialog sends user back to new Main Activity
                        } else {
                            // Pack data into wrapper
                            certDetailsWrapper.setChainLength(chain.length);
                            certDetailsWrapper.setAlias(alias);
                            certDetailsWrapper.setUserCert(chain[0]);

                            // Get the last in the chain for the CA cert
                            if (chain.length > 2) {     // if there's 3 or more certs total in chain
                                certDetailsWrapper.setCaCert(chain[(chain.length - 1)]);    // root CA is the top level certificate
                                certDetailsWrapper.setIntermediaryCert(chain[(chain.length - 2)]);  // intermediary is below the root
                            } else if (chain.length == 2) {     // there's only a user and ca cert
                                certDetailsWrapper.setCaCert(chain[(chain.length - 1)]);    // root CA is the top level certificate
                            } else //noinspection StatementWithEmptyBody
                                if (chain.length == 1) {     // Chain consists of just user and CA cert
                                // No cert chain exists...
                            }
                        }

                        // Start the View Certificate Chain Details activity
                        Intent intent = new Intent(MainActivity.this, Activity_ViewCertChainDetails.class);
                        Bundle bundle = new Bundle();
                        bundle.putSerializable("certDetailsWrapper", certDetailsWrapper);
                        intent.putExtras(bundle);
                        intent.setClass(MainActivity.this, Activity_ViewCertChainDetails.class);
                        startActivity(intent);
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
                    //MyCertificatesUtilities.showAlertDialog(MainActivity.this, getString(R.string.file_error_title), getString(R.string.error_message_file_read_error));
                    //return;

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
        final View myView = inflater.inflate(R.layout.p12_password_dialog, null);
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
        builder.create().show();
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
            // Show the About dialog
            // TODO - Programmatically populate the version number in the About dialog.
            new AlertDialog.Builder(MainActivity.this)
                    .setCancelable(true)
                    .setView(R.layout.about_dialog)
                    .create()
                    .show();

            return true;
        }

        // Show tips
        if (id == R.id.action_show_tips) {
            showTipsSequence(100, isThisFirstLaunch());
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    private boolean isThisFirstLaunch() {
        SharedPreferences myCertsSharedPref = getSharedPreferences(MyCertsConstants.MY_PREFS, MODE_PRIVATE);
        return myCertsSharedPref.getBoolean(MyCertsConstants.FIRST_LAUNCH, true);
    }

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
                    .setTitleText("Did you know?")
                    .setContentText("You may be prompted to enable a lock screen. This is because Android wants to protect your cryptographic keys from unauthorized users.")
                    .setDismissText("Okay!")
                    .build();

            MaterialShowcaseView issuerTip = new MaterialShowcaseView.Builder(this)
                    .setTarget(findViewById(R.id.btn_listCerts))
                    .setTitleText("Also...")
                    .setContentText("If an issuer certificate is present, you'll be able to see its details as well!")
                    .setDismissText("Got It!")
                    .build();

            MaterialShowcaseView startTip = new MaterialShowcaseView.Builder(this)
                    .setTarget(findViewById(R.id.btn_inspectFromFile))
                    .setTitleText("New feature!")
                    .setContentText("You can inspect certificates from a local file. This is helpful for inspecting a certificate prior to installing it. P12, PFX and PEM format certificate files are supported.")
                    .setDismissText("Got It!")
                    .build();

            tipsSequence.setConfig(config);
            tipsSequence.addSequenceItem(lockScreenTip);
            tipsSequence.addSequenceItem(issuerTip);
            tipsSequence.addSequenceItem(startTip);
            tipsSequence.start();
        }
    }

    /**
     * This is an alert that is displayed when the Android KeyChain returns a null
     * handle for the selected certificate. This would be a highly unusual instance.
     */
    private void alertBadAlias() {

        AlertDialog.Builder alertDialog = new AlertDialog.Builder(MainActivity.this);

        // If the user backs out of this activity, they forfeit objects created and go back to the main activity.
        alertDialog.setPositiveButton("OK", null);
        alertDialog.setMessage("Couldn't retrieve certificate details.");
        alertDialog.setTitle("My Certificates");
        alertDialog.show();
    }
}

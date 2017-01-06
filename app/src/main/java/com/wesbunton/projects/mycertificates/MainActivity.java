package com.wesbunton.projects.mycertificates;

import android.content.Intent;
import android.os.Bundle;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.security.KeyChainException;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;

import uk.co.deanwild.materialshowcaseview.MaterialShowcaseView;

/**
 * This is the class for the main activity of the My Certificates application.
 * This dialog will handle the main screen button(s) onClick behavior and the
 * menu options.
 */
public class MainActivity extends AppCompatActivity {

    private final String LOGTAG = MainActivity.class.getSimpleName();

    // String used to track if the tips should be launched
    private static final String SHOWCASE_ID = "tips sequence";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        // Show sequence of tips on first launch...
        showTipsSequence(500);  // half a second delay (in milliseconds)

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
                            } else if (chain.length == 1) {     // Chain consists of just user and CA cert
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
            showTipsOnDemand(500);
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    /**
     * This method will display a tip on the screen when the app is
     * first launched.
     * @param withDelay     Delay in milliseconds for the tip to be shown.
     */
    private void showTipsSequence(int withDelay) {
        new MaterialShowcaseView.Builder(this)
                .setTarget(findViewById(R.id.btn_listCerts))
                .setTitleText("Did you know?")
                .setDismissText("GOT IT!")
                .setContentText("You may be prompted to enable a lock screen to protect access to user certificates. Use this button to get started viewing your certs.")
                .setDelay(withDelay) // optional but starting animations immediately in onCreate can make them choppy
                .singleUse(SHOWCASE_ID) // provide a unique ID used to ensure it is only shown once
                .setShapePadding(96)
                .setFadeDuration(1000)
                .show();
    }

    /**
     * This method will display a tip on the screen when the app is
     * first launched.
     * @param withDelay     Delay in milliseconds for the tip to be shown.
     */
    private void showTipsOnDemand(int withDelay) {
        new MaterialShowcaseView.Builder(this)
                .setTarget(findViewById(R.id.btn_listCerts))
                .setTitleText("Did you know?")
                .setDismissText("GOT IT!")
                .setContentText("You may be prompted to enable a lock screen to protect access to user certificates. Use this button to get started viewing your certs.")
                .setDelay(withDelay) // optional but starting animations immediately in onCreate can make them choppy
                .setShapePadding(96)
                .setFadeDuration(1000)
                .show();
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

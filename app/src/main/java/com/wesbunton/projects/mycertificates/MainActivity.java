package com.wesbunton.projects.mycertificates;

import android.content.DialogInterface;
import android.content.Intent;
import android.os.Bundle;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.security.KeyChainException;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.LinearLayoutManager;
import android.support.v7.widget.RecyclerView;
import android.support.v7.widget.Toolbar;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;

public class MainActivity extends AppCompatActivity {

    private final String LOGTAG = MainActivity.class.getSimpleName();

    private RecyclerView recyclerView;
    private RecyclerView.Adapter adapter;
    private RecyclerView.LayoutManager layoutManager;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        // Code for showing tip cards here
        recyclerView = (RecyclerView) findViewById(R.id.recyclerTips);
        recyclerView.setHasFixedSize(true);
        layoutManager = new LinearLayoutManager(this);
        recyclerView.setLayoutManager(layoutManager);

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

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_about) {
            // Build the alert
            final AlertDialog.Builder alertDialog = new AlertDialog.Builder(MainActivity.this);
            alertDialog.setTitle("About My Certificates");
            alertDialog.setPositiveButton("OK", null);
            alertDialog.setMessage("Go to wesbunton.github.io more info");

            // TODO - Add reference for free icon
            // <div>Icons made by <a href="http://www.flaticon.com/authors/flat-icons" title="Flat Icons">Flat Icons</a> from <a href="http://www.flaticon.com" title="Flaticon">www.flaticon.com</a> is licensed by <a href="http://creativecommons.org/licenses/by/3.0/" title="Creative Commons BY 3.0" target="_blank">CC 3.0 BY</a></div>

            // Show the alert
            AlertDialog alert = alertDialog.create();
            alert.show();

            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    // Method used when user taps the back button on this activity,
    // if they select 'yes', they go back to the main activity rather than the last screen.
    private void alertBadAlias() {

        AlertDialog.Builder alertDialog = new AlertDialog.Builder(MainActivity.this);

        // If the user backs out of this activity, they forfeit objects created and go back to the main activity.
        alertDialog.setPositiveButton("OK", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                Intent intent = new Intent(MainActivity.this, MainActivity.class);
                intent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
                startActivity(intent);
            }
        });
        alertDialog.setMessage("Couldn't retrieve certificate details.");
        alertDialog.setTitle("My Certificates");
        alertDialog.show();
    }

}

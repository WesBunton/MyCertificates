package com.wesbunton.projects.mycertificates;

import android.app.FragmentManager;
import android.os.Bundle;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.support.v4.app.FragmentTransaction;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;

public class MainActivity extends AppCompatActivity {

    private final String LOGTAG = MainActivity.class.getSimpleName();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        // Show tip card
//        FragmentManager fragmentManager = getFragmentManager();
//        android.app.FragmentTransaction fragmentTransaction = fragmentManager.beginTransaction();

        Button btnListCerts = (Button) findViewById(R.id.btn_listCerts);
        btnListCerts.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                // Prompt user to select certificate
                KeyChain.choosePrivateKeyAlias(MainActivity.this, new KeyChainAliasCallback() {
                    @Override
                    public void alias(String alias) {

                        // Check if we're allowed access
                        if (alias == null) {
                            Log.d(LOGTAG, "Denied certificate access.");
                            return;
                        }
                    }
                }, new String[]{}, null, null, -1, null);
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

            // Show the alert
            AlertDialog alert = alertDialog.create();
            alert.show();

            return true;
        }

        return super.onOptionsItemSelected(item);
    }
}

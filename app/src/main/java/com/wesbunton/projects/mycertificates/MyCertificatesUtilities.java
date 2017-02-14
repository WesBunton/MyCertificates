package com.wesbunton.projects.mycertificates;

import android.content.Context;
import android.net.Uri;
import android.support.v7.app.AlertDialog;

import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter;
import org.spongycastle.openssl.PEMParser;
import org.spongycastle.util.io.pem.PemObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * The MyCertificatesUtilities class is comprised of static methods
 * to aid in cleaner and more readable code throughout the My Certificates
 * Android application. The caller may need to pass their context in
 * for more complex tasks that require UI access or other special cases.
 */
public class MyCertificatesUtilities {

    /**
     * This method will take a uri (from opening a file), and parse PEM data
     * and return the X509 Certificate Holder.
     * @param context   Caller's context.
     * @param uri       Uri from the file containing the PEM data.
     * @return          Returns an X509CertificateHolder.
     */
    static X509CertificateHolder parsePemFile(Context context, Uri uri) {
        try {
            InputStream inputStream = context.getContentResolver().openInputStream(uri);
            if (inputStream != null) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
                PEMParser pemParser = new PEMParser(reader);
                PemObject pemObject = pemParser.readPemObject();
                if (pemObject != null) {
                    return new X509CertificateHolder(pemObject.getContent());
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * This method converts an X509CertificateHolder object to a regular
     * X509Certificate object.
     * @param certHolder    Spongy Castle X509CertificateHolder object.
     * @return              Spongy Castle X509Certificate object.
     */
    static X509Certificate certConverter(X509CertificateHolder certHolder) {
        try {
            if (certHolder != null) {
                X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
                if (certificate != null) {
                    return certificate;
                }
            }
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * This method shows a generic alert dialog. This can be invoked for a number
     * of error scenarios, when the executing code block is simply going to return
     * without continuing, and the user needs to be shown some error information.
     * @param context   Context from the calling activity.
     * @param title     String to set the dialog title to.
     * @param message   String to set the dialog message to.
     */
    static void showAlertDialog(Context context, String title, String message) {
        AlertDialog.Builder alertDialog = new AlertDialog.Builder(context);
        alertDialog.setPositiveButton("OK", null);
        alertDialog.setTitle(title);
        alertDialog.setMessage(message);
        alertDialog.show();
    }
}

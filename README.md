# My Certificates

My Certificates is an Android application that allows users to view details of X509 user security certificates. This is useful as the Android settings applications will show very little information of user security certificates.

## Google Play Store Link  
The latest version is available in the Google Play Store:  
https://play.google.com/store/apps/details?id=com.wesbunton.projects.mycertificates

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. You can use the latest version from the Google Play Store now! If you'd like to build it from source, you can do so from the master branch of this repo.

## Quickstart Guide

Using the My Certificate Android application is dead simple. There are two buttons to list the available user certificates (either from KeyChain or a local file), and allowing access to one of those certificates will allow the application to parse the certificate and display the information to the user.

Note that none of this information is stored within the application. Once a user goes back to the main screen, all of the certificate information is forgotten. In fact, to display the information again, the user will need to again perform the explicit allowing of access to the certificate.

### Note about lock screen:  
Because the Android platform has security in mind when implementing the KeyChain security certificate store, the platform does require that users have a lock screen enabled to successfully store an X509 user certificate. You can store CA certificates for doing things like HTTPS/TLS connections without a lock screen.

When the application is launched for the first time, there is a tip shown reminding users that they system might prompt them to enable a lock screen during app use to protect their user certificates.

## Use cases:
**1. Install new certificate**  
Prerequisite:  
You need to have an X509 certificate within a P12 file local to your Android device.  

Steps:  
1. Launch My Certificates app.  
2. Select the "Select Certificate from Store" button. You'll see the Android user certificate selection screen. At the bottom of this dialog is an **Install** button. Select this.
3. Browse to your new certificate file. Select it.  
4. You'll be prompted to enter a password if the file is password protected (recommended for security certificates with private keys).  
5. You'll be prompted to enter a name for the certificate. This is how you'll see the certificate labeled within the list of user certificates.  
6. Finally, select whether you plan to use this certificate for VPN/app use or only for Wi-Fi authentication. Then tap **OK**.  

**2. View Details of installed certificate**  
Prerequisite:  
You need to have a user certificate installed on the device. Note that this is different from simply having a CA certificate.

Steps:  
1. Launch My Certificates app.  
2. Select the "Select Certificate" button. You'll see the Android user certificate selection screen. Select the certificate to examine, and tap the **ALLOW** button.  
3. You'll be shown a list of details for that specific user certificate. If there's other certificates within a certificate chain that include this certificate, such as its issuing CA/RA certificate, you can swipe sideways to view the details of those certificates as well.  

**3. View Details of certificate from local file**  
Prerequisite:  
File containing a certificate is present on the device.

Steps:  
1. Launch My Certificates app.  
2. Select the "Select Certificate from File" button. You'll see the Android file selector prompt. Select a certificate file containing a P12/PFX or PEM format certificate.  
3. If you've selected a P12/PFX, you'll be prompted to enter the password to decrypt it.  
3. You'll be shown a list of details for that specific user certificate.  

## Limitations

As previously noted, for security purposes, you cannot store and access user certificates without having a lock screen enabled. Additionally, you cannot disable the use of a lock screen when user certificates are present in the Android KeyChain.

My Certificates will allow you to install new user certificates, but you cannot delete a single user certificate unless you're running Nougat. This is how the Android KeyChain API has been implemented. This may change in future releases of Android, but for now the only way to delete user certificates is to go to: **Settings -> Security -> Clear credentials**. This will wipe **ALL user certificates**.

### New Features!

You can now select X509 certificates that are simply stored in PEM, P12, or PFX format in a local file. With this implementation, the user can inspect certificate files without having to install them, which is inconvenient due to Android clear-all certificate implementation.

Feel free to submit an issue to add a feature request!

## Built With

* This application was developed in the [Android Studio IDE v2.2.3](https://developer.android.com/studio/index.html).
* The JRE/JVM used was v1.8.0_11.
* This was most recently built for release using [Gradle v2.14.1](https://docs.gradle.org/current/userguide/userguide.html "Gradle Documentation").
* [Spongey Castle](https://rtyley.github.io/spongycastle/) - The crypto engine that is forked from Bouncy Castle and enables a lot of great crypto operations on Android.
* [MaterialShowcaseView](https://github.com/deano2390/MaterialShowcaseView) - an awesome overlay view that helped me show tips with a nice Material design.

### Building the Source

After cloning the repository, you should be able to build it in the repo directory using the local Gradle script.
```
# For linux machines:
./gradlew build
...
:app:testReleaseUnitTest
:app:test
:app:check
:app:build

BUILD SUCCESSFUL

Total time: 48.412 secs
```

## Running the tests

At this time, there are no automated tests being performed.

## Installing

Installation is a very straightforward process. If you built the application from source, the default output location, relative to the repo directory is: **app/build/outputs/apk/app-debug.apk**

To install this with ADB, perform:
```
adb install app/build/outputs/apk/app-debug.apk
```

## Authors

* **Wes Bunton** - *Initial work*

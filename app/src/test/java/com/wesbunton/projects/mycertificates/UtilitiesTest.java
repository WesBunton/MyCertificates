package com.wesbunton.projects.mycertificates;

import junit.framework.Assert;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

/**
 * Author: Wes Bunton
 * Date: October 2017
 *
 * This class contains basic unit tests for the Utilities class.
 */
@RunWith(RobolectricTestRunner.class)
public class UtilitiesTest {

    @Test
    public void isValidURL_DataSet1() {
        Assert.assertTrue(MyCertificatesUtilities.isValidUrl("www.google.com"));
    }

    @Test
    public void isValidURL_DataSet2() {
        Assert.assertTrue(MyCertificatesUtilities.isValidUrl("google.com"));
    }

    @Test
    public void isValidURL_DataSet3() {
        Assert.assertTrue(MyCertificatesUtilities.isValidUrl("http://www.google.com"));
    }

    @Test
    public void isValidURL_DataSet4() {
        Assert.assertTrue(MyCertificatesUtilities.isValidUrl("https://www.google.com"));
    }

    @Test
    public void isValidURL_DataSet5() {
        Assert.assertTrue(MyCertificatesUtilities.isValidUrl("www.google.io"));
    }

    @Test
    public void isValidURL_DataSet6() {
        Assert.assertFalse(MyCertificatesUtilities.isValidUrl("www.google"));
    }

    @Test
    public void isValidURL_DataSet7() {
        Assert.assertFalse(MyCertificatesUtilities.isValidUrl("htp://www.google.com"));
    }

    @Test
    public void isValidURL_DataSet8() {
        Assert.assertFalse(MyCertificatesUtilities.isValidUrl(""));
    }

    @Test
    public void isValidURL_DataSet9() {
        Assert.assertFalse(MyCertificatesUtilities.isValidUrl(".com"));
    }

    @Test
    public void parsePemFile_NullParam() {
        try {
            MyCertificatesUtilities.parsePemFile(null, null);
            Assert.fail("IllegalArgumentException should have been thrown.");
        } catch (IllegalArgumentException e) {
            // Success
        }
    }

    @Test
    public void certConverter_NullParams() {
        try {
            MyCertificatesUtilities.certConverter(null);
            Assert.fail("IllegalArgumentException should have been thrown.");
        } catch (IllegalArgumentException e) {
            // Success
        }
    }
}



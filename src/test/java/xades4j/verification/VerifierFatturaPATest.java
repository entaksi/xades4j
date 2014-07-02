package xades4j.verification;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import xades4j.algorithms.EnvelopedSignatureTransform;
import xades4j.production.*;
import xades4j.properties.DataObjectDesc;
import xades4j.providers.BasicSignatureOptionsProvider;
import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.KeyStoreKeyingDataProvider;
import xades4j.providers.impl.PKCS11KeyStoreKeyingDataProvider;
import xades4j.providers.impl.PKIXCertificateValidationProvider;
import xades4j.utils.XadesProfileResolutionException;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by luigi on 26/06/14.
 */
public class VerifierFatturaPATest extends VerifierTestBase
{
    XadesVerificationProfile verificationProfile;

    @Before
    public void initialize()
    {
        verificationProfile = new XadesVerificationProfile(VerifierTestBase.validationProviderMySigs);
    }

    @Test
    public void testVerifyBES() throws Exception
    {
        // verifica una FatturaPA firmata scaricata dal sito
        System.out.println("verifyBESFatturaPA");

        // the signed file was downloaded from here
        // http://fatturapa.gov.it/export/fatturazione/sdi/fatturapa/v1.0/IT01234567890_X1111.xml
        Element signatureNode = getSigElement(getDocument("fatturapa/IT01234567890_X1111.xml"));
        XAdESVerificationResult res = verificationProfile.newVerifier().verify(signatureNode, null);
        Assert.assertEquals(XAdESForm.BES, res.getSignatureForm());
    }

    @Test
    public void testVerifyFatturaPA() throws Exception
    {
        // verifica una FatturaPA firmata con Xades4j
        System.out.println("verifyFatturaPA");

        Element signatureNode = getSigElement(getDocument("out/IT01234567890_11111(signed).xml"));
        XAdESVerificationResult res = verificationProfile.newVerifier().verify(signatureNode, null);

        System.out.println(res.getSignatureForm());
        System.out.println(res.getSignatureAlgorithmUri());
        System.out.println(res.getSignedDataObjects().size());
        System.out.println(res.getQualifyingProperties().all().size());

        Assert.assertEquals(XAdESForm.BES, res.getSignatureForm());
    }

}

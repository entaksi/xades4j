package xades4j.verification;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Element;
import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.impl.PKIXCertificateValidationProvider;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.util.ArrayList;

/**
 * Created by luigi on 26/06/14.
 */
public class VerifierFatturaPATest extends VerifierTestBase
{
    XadesVerificationProfile verificationProfile;

    @Before
    public void initialize()
    {
        try
        {
            FileInputStream is = new FileInputStream("./src/test/cert/fatturapa/cacerts");
            KeyStore trustAnchors = KeyStore.getInstance(KeyStore.getDefaultType());
            String password = "changeit";
            trustAnchors.load(is, password.toCharArray());
            CertStore certs = CertStore.getInstance("Collection", new CollectionCertStoreParameters(new ArrayList()), "SUN");
            CertificateValidationProvider certValidator = new PKIXCertificateValidationProvider(trustAnchors, false, certs);
            verificationProfile = new XadesVerificationProfile(certValidator);
        } catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    @Test
    public void testVerifyBES() throws Exception
    {
        System.out.println("verifyFatturaPA");

        // the signed file was downloaded from here
        // http://fatturapa.gov.it/export/fatturazione/sdi/fatturapa/v1.0/IT01234567890_X1111.xml
        Element signatureNode = getSigElement(getDocument("fatturapa/IT01234567890_X1111.xml"));
        XAdESVerificationResult res = verificationProfile.newVerifier().verify(signatureNode, null);
        Assert.assertEquals(XAdESForm.BES, res.getSignatureForm());
    }

}

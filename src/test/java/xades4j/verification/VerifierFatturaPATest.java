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

    @Test
    public void testSignAndVerifyBES() throws Exception
    {
        System.out.println("signFatturaPA");

        XadesSigner signer = getSigner();

        Document docSource = getDocument("fatturapa/IT01234567890_11111.xml");

        DataObjectDesc dataObjRef = new DataObjectReference("")
                .withTransform(new EnvelopedSignatureTransform());
        //.withTransform(XPath2FilterTransform.XPath2Filter.subtract("/descendant::ds:Signature"));
        signer.sign(new SignedDataObjects(dataObjRef), docSource.getDocumentElement());

        outputDocument(docSource, "IT01234567890_11111(signed).xml");


        System.out.println("verifyFatturaPA");

        Element signatureNode = getSigElement(getDocument("out/IT01234567890_11111(signed).xml"));
        XAdESVerificationResult res = verificationProfile.newVerifier().verify(signatureNode, null);

        System.out.println(res.getSignatureForm());
        System.out.println(res.getSignatureAlgorithmUri());
        System.out.println(res.getSignedDataObjects().size());
        System.out.println(res.getQualifyingProperties().all().size());

        Assert.assertEquals(XAdESForm.BES, res.getSignatureForm());
    }

    private XadesSigner getSigner()
    {
        KeyStoreKeyingDataProvider.SigningCertSelector scs = new KeyStoreKeyingDataProvider.SigningCertSelector()
        {
            @Override
            public X509Certificate selectCertificate(List<X509Certificate> x509Certificates)
            {
                return x509Certificates.get(1);
            }
        };

        KeyStoreKeyingDataProvider.KeyStorePasswordProvider kspp = new KeyStoreKeyingDataProvider.KeyStorePasswordProvider()
        {
            @Override
            public char[] getPassword()
            {
                return "19111985".toCharArray();
            }
        };

        KeyStoreKeyingDataProvider.KeyEntryPasswordProvider kepp = new KeyStoreKeyingDataProvider.KeyEntryPasswordProvider()
        {
            @Override
            public char[] getPassword(String s, X509Certificate x509Certificate)
            {
                return "19111985".toCharArray();
            }
        };

        KeyingDataProvider keyingDataProvider = null;
        try
        {
            keyingDataProvider = new PKCS11KeyStoreKeyingDataProvider(
                    "/Users/luigi/Downloads/libbit4ipki.so",
                    "SmartCard",
                    scs,
                    kspp, kepp,
                    true);
            XadesSigningProfile signingProfile = new XadesBesSigningProfile(keyingDataProvider)
                    .withBasicSignatureOptionsProvider(new BasicSignatureOptionsProvider()
                    {
                        @Override
                        public boolean includeSigningCertificate()
                        {
                            return true;     // aggiunge il SigningCertificate e il keyInfo
                        }

                        @Override
                        public boolean includePublicKey()
                        {
                            return false;
                        }

                        @Override
                        public boolean signSigningCertificate()
                        {
                            return true;   // firma il keyinfo
                        }
                    });
            XadesSigner signer = signingProfile.newSigner();
            return signer;
        } catch (KeyStoreException e)
        {
            e.printStackTrace();
        } catch (XadesProfileResolutionException e)
        {
            e.printStackTrace();
        }
        return null;
    }

}

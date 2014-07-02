package xades4j.production;

import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Document;
import xades4j.algorithms.EnvelopedSignatureTransform;
import xades4j.properties.DataObjectDesc;
import xades4j.providers.BasicSignatureOptionsProvider;

/**
 * Created by luigi on 02/07/14.
 */
public class SignerFatturaPATest extends SignerTestBase
{

    @Test
    public void testSignFatturaPA() throws Exception
    {
        // firma una FatturaPA
        System.out.println("signFatturaPA");

        SignerBES signer = (SignerBES) new XadesBesSigningProfile(keyingProviderMy)
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
                })
                .newSigner();

        Document docSource = getDocument("fatturapa/IT01234567890_11111.xml");

        DataObjectDesc dataObjRef = new DataObjectReference("")
                .withTransform(new EnvelopedSignatureTransform());
        //.withTransform(XPath2FilterTransform.XPath2Filter.subtract("/descendant::ds:Signature"));
        XadesSignatureResult result = signer.sign(new SignedDataObjects(dataObjRef), docSource.getDocumentElement());

        outputDocument(docSource, "IT01234567890_11111(signed).xml");

        Assert.assertNotNull(result);
    }

}

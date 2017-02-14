/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.tests;

import de.rub.nds.tlsattacker.tls.util.CertificateFetcher;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsscanner.Report.TestResult;
import de.rub.nds.tlsscanner.flaw.ConfigurationFlaw;
import de.rub.nds.tlsscanner.tests.certificate.CertificateJudger;
import java.util.List;
import org.bouncycastle.jce.provider.X509CertificateObject;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateTest extends TLSTest {

    public CertificateTest(String serverHost) {
        super("CertificateTest", serverHost);
    }

    @Override
    public TestResult call() {
        TlsConfig config = new TlsConfig();
        config.setHost(this.getServerHost());
        X509CertificateObject serverCert = CertificateFetcher.fetchServerCertificate(config);
        CertificateJudger judger = new CertificateJudger();
        List<ConfigurationFlaw> flawList = judger.getFlaws(serverCert, getServerHost());
        if (flawList.isEmpty()) {
            return new TestResult(getTestName(), "false", "" + getTestName() + " bestanden");
        } else {
            StringBuilder builder = new StringBuilder("Der " + getTestName()
                    + " wurde nicht bestanden. Dies hat die folgenden Gründe: ");
            for (ConfigurationFlaw flaw : flawList) {
                builder.append(flaw.getFlawDescription());
            }
            return new TestResult(getTestName(), "true", builder.toString());
        }
    }

}

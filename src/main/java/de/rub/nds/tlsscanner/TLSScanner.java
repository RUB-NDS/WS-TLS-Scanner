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
package de.rub.nds.tlsscanner;

import de.rub.nds.tlsscanner.Report.SiteReport;
import de.rub.nds.tlsscanner.tests.CertificateTest;
import de.rub.nds.tlsscanner.tests.CiphersuiteOrderTest;
import de.rub.nds.tlsscanner.tests.CiphersuiteTest;
import de.rub.nds.tlsscanner.tests.HeartbleedTest;
import de.rub.nds.tlsscanner.tests.NamedCurvesTest;
import de.rub.nds.tlsscanner.tests.PaddingOracleTest;
import de.rub.nds.tlsscanner.tests.ProtocolVersionTest;
import de.rub.nds.tlsscanner.tests.SignatureAndHashAlgorithmTest;
import de.rub.nds.tlsscanner.tests.TLSTest;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.Future;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TLSScanner {

    private final ScanJobExecutor executor;
    private final String websiteHost;

    public TLSScanner(String websiteHost) {
        this.executor = new ScanJobExecutor(1);
        this.websiteHost = websiteHost;
    }

    public SiteReport scan() {
        List<TLSTest> testList = new LinkedList<>();
        testList.add(new CertificateTest(websiteHost));
        // testList.add(new ProtocolVersionTest(websiteHost));
        testList.add(new CiphersuiteTest(websiteHost));
        // testList.add(new CiphersuiteOrderTest(websiteHost));
        // testList.add(new HeartbleedTest(websiteHost));
        // testList.add(new NamedCurvesTest(websiteHost));
        // testList.add(new PaddingOracleTest(websiteHost));
        // testList.add(new SignatureAndHashAlgorithmTest(websiteHost));
        ScanJob job = new ScanJob(testList);
        return executor.execute(job);
    }

}

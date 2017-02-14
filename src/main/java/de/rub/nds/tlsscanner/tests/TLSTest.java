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

import de.rub.nds.tlsscanner.Report.TestResult;
import java.util.concurrent.Callable;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class TLSTest implements Callable<TestResult> {

    private String serverHost;
    private String testName;

    public TLSTest(String testName, String serverHost) {
        this.testName = testName;
        this.serverHost = serverHost;

    }

    public String getServerHost() {
        return serverHost;
    }

    public String getTestName() {
        return testName;
    }

    @Override
    public abstract TestResult call();
}

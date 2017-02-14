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

import de.rub.nds.tlsscanner.Report.TestResult;
import de.rub.nds.tlsscanner.Report.SiteReport;
import de.rub.nds.tlsscanner.tests.TLSTest;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ScanJobExecutor {
    private ExecutorService executor;

    public ScanJobExecutor(int threadCount) {
        executor = Executors.newFixedThreadPool(2);
    }

    public SiteReport execute(ScanJob scanJob) {
        List<Future<TestResult>> futureResults = new LinkedList<>();
        for (TLSTest test : scanJob.getTestList()) {
            futureResults.add(executor.submit(test));
        }
        List<TestResult> resultList = new LinkedList<>();
        for (Future<TestResult> testResult : futureResults) {
            try {
                resultList.add(testResult.get());
            } catch (InterruptedException | ExecutionException ex) {
                Logger.getLogger(ScanJobExecutor.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        executor.shutdown();
        return new SiteReport(resultList);
    }
}

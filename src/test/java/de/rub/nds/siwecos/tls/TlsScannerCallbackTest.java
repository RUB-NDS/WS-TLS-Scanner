/**
 *  SIWECOS-TLS-Scanner - A Webservice for the TLS-Scanner Module of TLS-Attacker
 *
 *  Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.siwecos.tls;

import de.rub.nds.siwecos.tls.json.ScanResult;
import de.rub.nds.siwecos.tls.ws.ScanRequest;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.crypto.tls.Certificate;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TlsScannerCallbackTest {

    private TlsScannerCallback callback;

    private ScanResult result;

    public TlsScannerCallbackTest() {
    }

    @Before
    public void setUp() {
        callback = new TlsScannerCallback(new ScanRequest("localhost", 4433, new String[] { "127.0.0.1:8080" }));
        SiteReport report = new SiteReport("google.de");
        report.setCertificate(Certificate.EMPTY_CHAIN);
        report.setCipherSuites(new ArrayList<>(Arrays.asList(CipherSuite.values())));
        for (Field field : report.getClass().getDeclaredFields()) {
            field.setAccessible(true);
            if (field.getType().equals(Boolean.class)) {
                try {
                    field.set(report, Boolean.TRUE);
                } catch (IllegalArgumentException | IllegalAccessException ex) {
                    ex.printStackTrace();
                }
            }
        }
        result = callback.reportToScanResult(report);

    }

    /**
     * Test of run method, of class TlsScannerCallback.
     */
    @Test
    public void testJson() {
        System.out.println(callback.scanResultToJson(result));
    }

    /**
     * Test of answer method, of class TlsScannerCallback.
     */
    @Test
    public void testAnswer() {
    }

}

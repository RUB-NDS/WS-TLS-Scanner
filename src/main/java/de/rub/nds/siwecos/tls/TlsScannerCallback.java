/**
 *  SIWECOS-TLS-Scanner - A Webservice for the TLS-Scanner Module of TLS-Attacker
 *
 *  Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 */
package de.rub.nds.siwecos.tls;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import de.rub.nds.siwecos.tls.json.ScanResult;
import de.rub.nds.siwecos.tls.json.TestResult;
import de.rub.nds.siwecos.tls.json.TranslateableMessage;
import de.rub.nds.siwecos.tls.ws.ScanRequest;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsscanner.TlsScanner;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.Charset;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class TlsScannerCallback implements Runnable {

    protected static final org.apache.logging.log4j.Logger LOGGER = LogManager.getLogger(TlsScannerCallback.class
            .getName());

    private ScanRequest request;

    public TlsScannerCallback(ScanRequest request) {
        this.request = request;
    }

    @Override
    public void run() {
        ScannerConfig scannerConfig = new ScannerConfig(new GeneralDelegate());
        scannerConfig.setDangerLevel(request.getDangerLevel());
        ClientDelegate delegate = (ClientDelegate) scannerConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(request.getUrl());
        TlsScanner scanner = new TlsScanner(scannerConfig);
        SiteReport report = scanner.scan();
        ScanResult result = reportToScanResult(report);
        answer(result);
    }

    public String scanResultToJson(ScanResult result) {
        ObjectWriter ow = new ObjectMapper().writer().withDefaultPrettyPrinter();
        String json = "";
        try {
            json = ow.writeValueAsString(result);
        } catch (JsonProcessingException ex) {
            LOGGER.warn("Could not convert to json");
            ex.printStackTrace();
        }
        return json;
    }

    public void answer(ScanResult result) {
        String json = scanResultToJson(result);
        for (String callback : request.getCallbackurls()) {
            try {
                URL url = new URL(callback);
                URLConnection con = url.openConnection();
                HttpURLConnection http = (HttpURLConnection) con;
                con.setDoOutput(true);
                http.setRequestMethod("POST");
                http.setChunkedStreamingMode(4096);
                http.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
                http.connect();
                try (OutputStream os = http.getOutputStream()) {
                    os.write(json.getBytes(Charset.forName("UTF-8")));
                }
            } catch (IOException ex) {
                LOGGER.warn("Failed to callback:" + callback, ex);
            }
        }
    }

    public ScanResult reportToScanResult(SiteReport report) {
        List<TestResult> resultList = new LinkedList<>();
        resultList.add(getHttpsResponse(report));
        resultList.add(getHttpsSupported(report));
        resultList.add(getCertificateExpired(report));
        resultList.add(getCertificateNotValidYet(report));
        resultList.add(getCertificateNotSentByServer(report));
        resultList.add(getCertificateWeakHashFunction(report));
        resultList.add(getCertificateWeakSignAlgorithm(report));
        resultList.add(getSupportsAnon(report));
        resultList.add(getSupportsExport(report));
        resultList.add(getSupportsNull(report));
        resultList.add(getSupportsRc4(report));
        resultList.add(getCipherSuiteOrder(report));
        resultList.add(getSupportsSsl2(report));
        resultList.add(getSupportsSsl3(report));
        resultList.add(getBleichenbacherVulnerable(report));
        resultList.add(getCrimeVulnerable(report));
        resultList.add(getHeartbleedVulnerable(report));
        resultList.add(getInvalidCurveEphemeralVulnerable(report));
        resultList.add(getInvalidCurveVulnerable(report));
        resultList.add(getPaddingOracleVulnerable(report));
        resultList.add(getPoodleVulnerable(report));
        resultList.add(getTlsPoodleVulnerable(report));
        resultList.add(getSupportsDes(report));
        resultList.add(getSupportsTls13(report));
        resultList.add(getSweet32Vulnerable(report));

        int lowest = 100;
        boolean hasError = false;
        for (TestResult result : resultList) {
            if (result.getScore() < lowest) {
                lowest = result.getScore();
            }
            hasError |= result.isHasError();
        }
        ScanResult result = new ScanResult("TLS", false, null, lowest, resultList);
        return result;
    }

    private TestResult getHttpsResponse(SiteReport report) {
        return new TestResult("HTTPS_NO_RESPONSE", report.getServerIsAlive() == null, null,
                report.getServerIsAlive() == Boolean.TRUE ? 100 : 0,
                report.getServerIsAlive() == Boolean.TRUE ? "success" : "critical", null);
    }

    private TestResult getHttpsSupported(SiteReport report) {
        return new TestResult("HTTPS_NOT_SUPPORTED", report.getSupportsSslTls() == null, null,
                report.getSupportsSslTls() == Boolean.TRUE ? 100 : 0,
                report.getSupportsSslTls() == Boolean.TRUE ? "hidden" : "critical", null);
    }

    private TestResult getCertificateExpired(SiteReport report) {
        return new TestResult("CERTIFICATE_EXPIRED", report.getCertificateExpired() == null, null,
                report.getCertificateExpired() ? 0 : 100, !report.getCertificateExpired() == Boolean.TRUE ? "success"
                        : "critical", null);
    }

    private TestResult getCertificateNotValidYet(SiteReport report) {
        return new TestResult("CERTIFICATE_NOT_VALID_YET", report.getCertificateNotYetValid() == null, null,
                report.getCertificateNotYetValid() ? 0 : 100,
                !report.getCertificateNotYetValid() == Boolean.TRUE ? "success" : "critical", null);
    }

    private TestResult getCertificateNotSentByServer(SiteReport report) {
        if (report.getCertificate() == null) {
            return new TestResult("CERTIFICATE_NOT_SENT_BY_SERVER", report.getCertificate() == null, null, 0,
                    "critical", null);
        }
        return new TestResult("CERTIFICATE_NOT_SENT_BY_SERVER", report.getCertificate() == null, null, report
                .getCertificate().getLength() > 0 ? 100 : 0, report.getCertificate().getLength() > 0 ? "hidden"
                : "critical", null);
    }

    private TestResult getCertificateWeakHashFunction(SiteReport report) {
        return new TestResult("CERTIFICATE_WEAK_HASH_FUNCTION", report.getCertificateHasWeakHashAlgorithm() == null,
                null, report.getCertificateHasWeakHashAlgorithm() ? 0 : 100,
                !report.getCertificateHasWeakHashAlgorithm() == Boolean.TRUE ? "success" : "critical", null);
    }

    private TestResult getCertificateWeakSignAlgorithm(SiteReport report) {
        return new TestResult("CERTIFICATE_WEAK_SIGN_ALGO", report.getCertificateHasWeakSignAlgorithm() == null, null,
                report.getCertificateHasWeakSignAlgorithm() ? 0 : 100,
                !report.getCertificateHasWeakSignAlgorithm() == Boolean.TRUE ? "hidden" : "critical", null);
    }

    private TestResult getSupportsAnon(SiteReport report) {
        List<TranslateableMessage> messageList = new LinkedList<>();
        List<CipherSuite> suiteList = new LinkedList<>();
        for (CipherSuite suite : report.getCipherSuites()) {
            if (suite.name().contains("anon")) {
                suiteList.add(suite);
            }
        }
        messageList.add(new TranslateableMessage("ANON_SUITES", suiteList));
        return new TestResult("CIPHERSUITE_ANON", report.getSupportsAnonCiphers() == null, null,
                report.getSupportsAnonCiphers() == Boolean.TRUE ? 0 : 100,
                !(report.getSupportsAnonCiphers() == Boolean.TRUE) ? "success" : "critical", messageList);
    }

    private TestResult getSupportsExport(SiteReport report) {
        List<TranslateableMessage> messageList = new LinkedList<>();
        List<CipherSuite> suiteList = new LinkedList<>();
        for (CipherSuite suite : report.getCipherSuites()) {
            if (suite.name().toUpperCase().contains("EXPORT")) {
                suiteList.add(suite);
            }
        }
        messageList.add(new TranslateableMessage("EXPORT_SUITES", suiteList));
        return new TestResult("CIPHERSUITE_EXPORT", report.getSupportsExportCiphers() == null, null,
                report.getSupportsExportCiphers() == Boolean.TRUE ? 0 : 100,
                !(report.getSupportsExportCiphers() == Boolean.TRUE) ? "success" : "critical", messageList);
    }

    private TestResult getSupportsNull(SiteReport report) {
        List<TranslateableMessage> messageList = new LinkedList<>();
        List<CipherSuite> suiteList = new LinkedList<>();
        for (CipherSuite suite : report.getCipherSuites()) {
            if (suite.name().toUpperCase().contains("NULL")) {
                suiteList.add(suite);
            }
        }
        messageList.add(new TranslateableMessage("NULL_SUITES", suiteList));
        return new TestResult("CIPHERSUITE_NULL", report.getSupportsNullCiphers() == null, null,
                report.getSupportsNullCiphers() == Boolean.TRUE ? 0 : 100,
                !(report.getSupportsNullCiphers() == Boolean.TRUE) ? "success" : "critical", messageList);
    }

    private TestResult getSupportsRc4(SiteReport report) {
        List<TranslateableMessage> messageList = new LinkedList<>();
        List<CipherSuite> suiteList = new LinkedList<>();
        for (CipherSuite suite : report.getCipherSuites()) {
            if (suite.name().toUpperCase().contains("RC4")) {
                suiteList.add(suite);
            }
        }
        messageList.add(new TranslateableMessage("RC4_SUITES", suiteList));
        return new TestResult("CIPHERSUITE_RC4", report.getSupportsRc4Ciphers() == null, null,
                report.getSupportsRc4Ciphers() == Boolean.TRUE ? 30 : 100,
                !(report.getSupportsRc4Ciphers() == Boolean.TRUE) ? "success" : "warning", messageList);
    }

    private TestResult getCipherSuiteOrder(SiteReport report) {
        return new TestResult("CIPHERSUITEORDER_ENFORCED", report.getEnforcesCipherSuiteOrdering() == null, null,
                report.getEnforcesCipherSuiteOrdering() == Boolean.TRUE ? 90 : 100,
                (report.getEnforcesCipherSuiteOrdering() == Boolean.TRUE) ? "success" : "warning", null);
    }

    private TestResult getSupportsSsl2(SiteReport report) {
        return new TestResult("PROTOCOLVERSION_SSL2", report.getSupportsSsl2() == null, null,
                report.getSupportsSsl2() == Boolean.TRUE ? 0 : 100,
                !(report.getSupportsSsl3() == Boolean.TRUE) ? "success" : "critical", null);
    }

    private TestResult getSupportsSsl3(SiteReport report) {
        return new TestResult("PROTOCOLVERSION_SSL3", report.getSupportsSsl3() == null, null,
                report.getSupportsSsl3() == Boolean.TRUE ? 0 : 100,
                !(report.getSupportsSsl3() == Boolean.TRUE) ? "success" : "critical", null);
    }

    private TestResult getBleichenbacherVulnerable(SiteReport report) {
        return new TestResult("BLEICHENBACHER_VULNERABLE", report.getBleichenbacherVulnerable() == null, null,
                report.getBleichenbacherVulnerable() == Boolean.TRUE ? 0 : 100,
                !(report.getBleichenbacherVulnerable() == Boolean.TRUE) ? "success" : "critical", null);
    }

    private TestResult getPaddingOracleVulnerable(SiteReport report) {
        return new TestResult("PADDING_ORACLE_VULNERABLE", report.getPaddingOracleVulnerable() == null, null,
                report.getPaddingOracleVulnerable() == Boolean.TRUE ? 0 : 100,
                !(report.getPaddingOracleVulnerable() == Boolean.TRUE) ? "success" : "critical", null);
    }

    private TestResult getInvalidCurveVulnerable(SiteReport report) {
        return new TestResult("INVALID_CURVE_VULNERABLE", report.getInvalidCurveVulnerable() == null, null,
                report.getInvalidCurveVulnerable() == Boolean.TRUE ? 0 : 100,
                !(report.getInvalidCurveVulnerable() == Boolean.TRUE) ? "success" : "critical", null);
    }

    private TestResult getInvalidCurveEphemeralVulnerable(SiteReport report) {
        return new TestResult("INVALID_CURVE_EPHEMERAL_VULNERABLE",
                report.getInvalidCurveEphermaralVulnerable() == null, null,
                report.getInvalidCurveEphermaralVulnerable() == Boolean.TRUE ? 0 : 100,
                !(report.getInvalidCurveEphermaralVulnerable() == Boolean.TRUE) ? "success" : "warning", null);
    }

    private TestResult getPoodleVulnerable(SiteReport report) {
        return new TestResult("POODLE_VULNERABLE", report.getPoodleVulnerable() == null, null,
                report.getPoodleVulnerable() == Boolean.TRUE ? 0 : 100,
                !(report.getPoodleVulnerable() == Boolean.TRUE) ? "success" : "critical", null);
    }

    private TestResult getTlsPoodleVulnerable(SiteReport report) {
        return new TestResult("TLS_POODLE_VULNERABLE", report.getTlsPoodleVulnerable() == null, null,
                report.getTlsPoodleVulnerable() == Boolean.TRUE ? 0 : 100,
                !(report.getTlsPoodleVulnerable() == Boolean.TRUE) ? "success" : "critical", null);
    }

    private TestResult getCrimeVulnerable(SiteReport report) {
        return new TestResult("CRIME_VULNERABLE", report.getCrimeVulnerable() == null, null,
                report.getCrimeVulnerable() == Boolean.TRUE ? 0 : 100,
                !(report.getCrimeVulnerable() == Boolean.TRUE) ? "success" : "critical", null);
    }

    private TestResult getSweet32Vulnerable(SiteReport report) {
        return new TestResult("SWEET32_VULNERABLE", report.getSweet32Vulnerable() == null, null,
                report.getSweet32Vulnerable() == Boolean.TRUE ? 80 : 100,
                !(report.getSweet32Vulnerable() == Boolean.TRUE) ? "success" : "warning", null);
    }

    private TestResult getHeartbleedVulnerable(SiteReport report) {
        return new TestResult("HEARTBLEED_VULNERABLE", report.getHeartbleedVulnerable() == null, null,
                report.getHeartbleedVulnerable() == Boolean.TRUE ? 0 : 100,
                !(report.getHeartbleedVulnerable() == Boolean.TRUE) ? "success" : "critical", null);
    }

    private TestResult getSupportsTls13(SiteReport report) {
        return new TestResult("PROTOCOLVERSION_TLS13", report.supportsAnyTls13() == null, null,
                report.supportsAnyTls13() == Boolean.TRUE ? 100 : 0, "bonus", null);
    }

    private TestResult getSupportsDes(SiteReport report) {
        List<TranslateableMessage> messageList = new LinkedList<>();
        List<CipherSuite> suiteList = new LinkedList<>();
        for (CipherSuite suite : report.getCipherSuites()) {
            if (suite.name().toUpperCase().contains("_DES")) {
                suiteList.add(suite);
            }
        }
        messageList.add(new TranslateableMessage("DES_SUITES", suiteList));
        return new TestResult("CIPHERSUITE_DES", report.getSupportsDesCiphers() == null, null,
                report.getSupportsDesCiphers() == Boolean.TRUE ? 0 : 100,
                !(report.getSupportsDesCiphers() == Boolean.TRUE) ? "success" : "warning", messageList);
    }

}

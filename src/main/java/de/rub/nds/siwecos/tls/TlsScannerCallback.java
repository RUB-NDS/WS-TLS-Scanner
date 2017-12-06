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

import de.rub.nds.siwecos.tls.ws.JsonResult;
import de.rub.nds.siwecos.tls.ws.ScanRequest;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsscanner.TLSScanner;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import sun.net.www.http.HttpClient;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class TlsScannerCallback implements Runnable {

    private ScanRequest request;

    public TlsScannerCallback(ScanRequest request) {
        this.request = request;
    }

    @Override
    public void run() {
        ScannerConfig scannerConfig = new ScannerConfig(new GeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) scannerConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(request.getUrl());

        TLSScanner scanner = new TLSScanner(scannerConfig);
        SiteReport report = scanner.scan();
        JsonResult result = new JsonResult(report);
        answer(result);
    }

    public void answer(JsonResult result) {
        for (String callback : request.getCallbackurls()) {
            try {
                URL url = new URL(callback);
                URLConnection con = url.openConnection();
                HttpURLConnection http = (HttpURLConnection) con;
                http.setRequestMethod("POST");
                http.setChunkedStreamingMode(4096);
                http.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
                http.connect();
                try (OutputStream os = http.getOutputStream()) {
                    os.write(result.getJsonEncoded().getBytes());
                }
            } catch (IOException ex) {
                Logger.getLogger(TlsScannerCallback.class.getName()).log(Level.WARNING,
                        "Failed to callback:" + callback, ex);
            }
        }
    }

}

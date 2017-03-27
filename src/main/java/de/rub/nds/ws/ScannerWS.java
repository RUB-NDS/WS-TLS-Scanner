/**
 *  SIWECOS-TLS-Scanner - A Webservice for the TLS-Scanner Module of TLS-Attacker
 *
 *  Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 */
package de.rub.nds.ws;

import de.rub.nds.tlsattacker.tls.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.GeneralDelegate;
import de.rub.nds.tlsscanner.TLSScanner;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.io.InputStream;
import java.net.URISyntaxException;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.UriInfo;
import javax.xml.bind.JAXB;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
@Path("ScannerWS")
public class ScannerWS {

    @Context
    private UriInfo context;

    @GET
    @Produces("application/json;charset=utf-8")
    @Path("{host}")
    public String getJson(@PathParam("host") String host) throws URISyntaxException {
        InputStream stream = ScannerWS.class.getResourceAsStream("/default.xml");
        WebServiceConfig config = JAXB.unmarshal(stream, WebServiceConfig.class);
        ScannerConfig scannerConfig = new ScannerConfig(new GeneralDelegate());
        scannerConfig.setLanguage(config.getLanguage());
        ClientDelegate delegate = (ClientDelegate) scannerConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(host);
        TLSScanner scanner = new TLSScanner(scannerConfig);
        SiteReport report = scanner.scan();
        return new JsonResult(report, config.isUseShortTest()).getJsonEncoded();
    }

}

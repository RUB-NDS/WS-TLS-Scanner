/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.ws;

import de.rub.nds.tlsscanner.Report.SiteReport;
import de.rub.nds.tlsscanner.TLSScanner;
import java.util.concurrent.ExecutorService;
import javax.jws.WebService;
import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.container.AsyncResponse;
import javax.ws.rs.container.Suspended;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.UriInfo;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
@Path("ScannerWS")
public class ScannerWS {

    @Context
    private UriInfo context;

    @GET
    @Produces("application/json")
    @Path("{host}")
    public String getJson(@PathParam("host")String host) {
        TLSScanner scanner = new TLSScanner(host);
        SiteReport report = scanner.scan();
        return report.getJsonReport();
    }

}

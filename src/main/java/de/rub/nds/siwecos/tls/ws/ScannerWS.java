/**
 *  SIWECOS-TLS-Scanner - A Webservice for the TLS-Scanner Module of TLS-Attacker
 *
 *  Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 */
package de.rub.nds.siwecos.tls.ws;

import de.rub.nds.siwecos.tls.TlsScannerCallback;
import java.net.URISyntaxException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
@Path("/")
@Consumes(MediaType.APPLICATION_JSON)
public class ScannerWS {

    @Context
    private UriInfo context;

    private ExecutorService service;

    public ScannerWS() {
        service = new ThreadPoolExecutor(2, 10, 10, TimeUnit.MINUTES, new LinkedBlockingDeque<Runnable>());
    }

    @POST
    @Path("/start")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response startScan(ScanRequest request) throws URISyntaxException {
        service.submit(new TlsScannerCallback(request));
        return Response.status(Response.Status.OK).entity("Success").type(MediaType.TEXT_PLAIN_TYPE).build();
    }

}

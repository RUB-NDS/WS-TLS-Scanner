/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
import de.rub.nds.tlsscanner.report.ProbeResult;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.ws.JsonResult;
import java.util.LinkedList;
import java.util.List;
import javax.json.Json;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class Main {
    public static void main(String args[]) {
        List<ProbeResult> resultList = new LinkedList<>();

        JsonResult result = new JsonResult(new SiteReport("google.com", resultList));
        System.out.println(result.getJsonEncoded());
    }
}

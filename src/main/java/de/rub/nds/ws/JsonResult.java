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
package de.rub.nds.ws;

import de.rub.nds.tlsscanner.report.ProbeResult;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.check.TLSCheck;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;
import javax.json.Json;
import javax.json.JsonObjectBuilder;
import javax.json.JsonWriter;
import javax.json.JsonWriterFactory;
import javax.json.stream.JsonGenerator;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class JsonResult {

    private SiteReport report;

    public JsonResult(SiteReport report) {
        this.report = report;
    }

    public String getJsonEncoded() {
        JsonObjectBuilder resultBuilder = Json.createObjectBuilder();
        JsonObjectBuilder checkBuilder = Json.createObjectBuilder();
        for (ProbeResult result : report.getResultList()) {
            for (TLSCheck check : result.getCheckList()) {
                JsonObjectBuilder singleCheckBuilder = Json.createObjectBuilder();
                singleCheckBuilder.add("result", check.isResult());
                singleCheckBuilder.add("description", check.getDescription());
                checkBuilder.add(check.getName(), singleCheckBuilder);
            }

        }
        resultBuilder.add("checks", checkBuilder);
        Map<String, Object> properties = new HashMap<>(1);
        properties.put(JsonGenerator.PRETTY_PRINTING, true);
        StringWriter sw = new StringWriter();
        JsonWriterFactory writerFactory = Json.createWriterFactory(properties);
        JsonWriter jsonWriter = writerFactory.createWriter(sw);

        jsonWriter.writeObject(resultBuilder.build());
        jsonWriter.close();

        return sw.toString();
    }
}

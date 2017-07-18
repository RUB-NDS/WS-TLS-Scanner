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

    private final SiteReport report;
    
    public JsonResult(SiteReport report) {
        this.report = report;
    }

    public String getJsonEncoded() {
        JsonObjectBuilder resultBuilder = Json.createObjectBuilder();
        JsonObjectBuilder checkBuilder = Json.createObjectBuilder();
        for (ProbeResult result : report.getResultList()) {
            for (TLSCheck check : result.getCheckList()) {
                JsonObjectBuilder singleCheckBuilder = Json.createObjectBuilder();
                if (check != null) {
                    singleCheckBuilder.add("result", check.isResult());
                    // singleCheckBuilder.add("description",
                    // check.getDescription());
                    if (check.isResult()) {
                        singleCheckBuilder.add("risk", check.getScore());

                    } else {
                        singleCheckBuilder.add("risk", 0);

                    }
                    checkBuilder.add(check.getType().name(), singleCheckBuilder);
                }
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

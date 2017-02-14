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
package de.rub.nds.tlsscanner.Report;

import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class SiteReport {

    private List<TestResult> resultList;

    public SiteReport(List<TestResult> resultList) {
        this.resultList = resultList;
    }

    // JSon magic
    public String getJsonReport() {
        StringBuilder builder = new StringBuilder();
        builder.append("{\n");
        builder.append("\t \"checks\": [\n");
        for (TestResult result : resultList) {
            builder.append(result.toJson());
        }
        builder.append("\t]\n");
        builder.append("}\n");
        return builder.toString();
    }
}

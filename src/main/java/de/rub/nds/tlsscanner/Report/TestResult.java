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

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TestResult {
    private String testName;
    private String result;
    private String description;

    public TestResult(String testName, String result, String description) {
        this.testName = testName;
        this.result = result;
        this.description = description;
    }

    public String toJson() {
        StringBuilder builder = new StringBuilder();
        builder.append("\t\t\"" + testName + "\": {\n");
        builder.append("\t\t\t\"result\": " + result + "\n");
        builder.append("\t\t\t\"description\": \"" + description + "\"\n");
        builder.append("\t\t}\n");
        return builder.toString();
    }
}

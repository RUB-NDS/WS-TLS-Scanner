/**
 *  SIWECOS-TLS-Scanner - A Webservice for the TLS-Scanner Module of TLS-Attacker
 *
 *  Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.siwecos.tls.json;

import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ScanResult {
    private String name;

    private boolean hasError;

    private TranslateableMessage errorMessage;

    private int score;

    private List<TestResult> tests;

    public ScanResult(String name, boolean hasError, TranslateableMessage errorMessage, int score,
            List<TestResult> tests) {
        this.name = name;
        this.hasError = hasError;
        this.errorMessage = errorMessage;
        this.score = score;
        this.tests = tests;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public boolean isHasError() {
        return hasError;
    }

    public void setHasError(boolean hasError) {
        this.hasError = hasError;
    }

    public TranslateableMessage getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(TranslateableMessage errorMessage) {
        this.errorMessage = errorMessage;
    }

    public int getScore() {
        return score;
    }

    public void setScore(int score) {
        this.score = score;
    }

    public List<TestResult> getTests() {
        return tests;
    }

    public void setTests(List<TestResult> tests) {
        this.tests = tests;
    }
}

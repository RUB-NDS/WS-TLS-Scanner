/**
 *  SIWECOS-TLS-Scanner - A Webservice for the TLS-Scanner Module of TLS-Attacker
 *
 *  Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 */
package de.rub.nds.siwecos.tls.json;

import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TestResult {

    private String name;

    private boolean hasError;

    private TranslateableMessage errorMessage;

    private int score;

    private String scoreType;

    private TranslateableMessage[] testDetails;

    public TestResult(String name, boolean hasError, TranslateableMessage errorMessage, int score, String scoreType,
            List<TranslateableMessage> testDetails) {
        this.name = name;
        this.hasError = hasError;
        this.errorMessage = errorMessage;
        this.score = score;
        this.scoreType = scoreType;
        if (testDetails != null) {
            this.testDetails = testDetails.toArray(new TranslateableMessage[testDetails.size()]);
        } else {
            this.testDetails = null;
        }
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

    public String getScoreType() {
        return scoreType;
    }

    public void setScoreType(String scoreType) {
        this.scoreType = scoreType;
    }

    public TranslateableMessage[] getTestDetails() {
        return testDetails;
    }

    public void setTestDetails(TranslateableMessage[] testDetails) {
        this.testDetails = testDetails;
    }
}

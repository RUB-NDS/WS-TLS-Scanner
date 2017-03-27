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

import de.rub.nds.tlsscanner.config.Language;
import java.io.Serializable;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class WebServiceConfig implements Serializable {

    private boolean useShortTest;
    private Language language;

    public WebServiceConfig() {
        this.language = Language.GERMAN;
        this.useShortTest = true;
    }

    public Language getLanguage() {
        return language;
    }

    public void setLanguage(Language language) {
        this.language = language;
    }

    public boolean isUseShortTest() {
        return useShortTest;
    }

    public void setUseShortTest(boolean useShortTest) {
        this.useShortTest = useShortTest;
    }
}

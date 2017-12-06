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

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */

public class ScanRequest {

    private String url;

    private int dangerLevel;

    private String[] callbackurls;

    public ScanRequest(String url, int dangerLevel, String[] callbackurls) {
        this.url = url;
        this.dangerLevel = dangerLevel;
        this.callbackurls = callbackurls;
    }

    public ScanRequest() {
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public int getDangerLevel() {
        return dangerLevel;
    }

    public void setDangerLevel(int dangerLevel) {
        this.dangerLevel = dangerLevel;
    }

    public String[] getCallbackurls() {
        return callbackurls;
    }

    public void setCallbackurls(String[] callbackurls) {
        this.callbackurls = callbackurls;
    }

    @Override
    public String toString() {
        return "ScanRequest{" + "url=" + url + ", dangerLevel=" + dangerLevel + ", callbackurls=" + callbackurls + '}';
    }
}

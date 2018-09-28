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

public class DebugOutput {

    private Integer initialQueueLenght;

    private Integer finalQueueSize;

    private Long timeInQueue;

    private Long enteredQueueAt;

    private Long leftQueueAt;

    private Long scanStartedAt;

    private Long scanFinisedAt;

    public DebugOutput(Integer initialQueueLenght, long enteredQueueAt) {
        this.initialQueueLenght = initialQueueLenght;
        this.enteredQueueAt = enteredQueueAt;
    }

    public Integer getInitialQueueLenght() {
        return initialQueueLenght;
    }

    public void setInitialQueueLenght(Integer initialQueueLenght) {
        this.initialQueueLenght = initialQueueLenght;
    }

    public Integer getFinalQueueSize() {
        return finalQueueSize;
    }

    public void setFinalQueueSize(Integer finalQueueSize) {
        this.finalQueueSize = finalQueueSize;
    }

    public Long getTimeInQueue() {
        return timeInQueue;
    }

    public void setTimeInQueue(Long timeInQueue) {
        this.timeInQueue = timeInQueue;
    }

    public Long getEnteredQueueAt() {
        return enteredQueueAt;
    }

    public void setEnteredQueueAt(Long enteredQueueAt) {
        this.enteredQueueAt = enteredQueueAt;
    }

    public Long getLeftQueueAt() {
        return leftQueueAt;
    }

    public void setLeftQueueAt(Long leftQueueAt) {
        this.leftQueueAt = leftQueueAt;
    }

    public Long getScanStartedAt() {
        return scanStartedAt;
    }

    public void setScanStartedAt(Long scanStartedAt) {
        this.scanStartedAt = scanStartedAt;
    }

    public Long getScanFinisedAt() {
        return scanFinisedAt;
    }

    public void setScanFinisedAt(Long scanFinisedAt) {
        this.scanFinisedAt = scanFinisedAt;
    }

}

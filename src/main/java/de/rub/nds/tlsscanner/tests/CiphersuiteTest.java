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
package de.rub.nds.tlsscanner.tests;

import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.ArbitraryMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.util.LogLevel;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsscanner.Report.TestResult;
import de.rub.nds.tlsscanner.flaw.ConfigurationFlaw;
import de.rub.nds.tlsscanner.flaw.FlawLevel;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CiphersuiteTest extends TLSTest {

    private static CipherSuite blacklistedCiphersuites[] = {};

    public CiphersuiteTest(String serverHost) {
        super("CiphersuiteTest", serverHost);
    }

    @Override
    public TestResult call() {
        List<CipherSuite> supportedCiphersuites = new LinkedList<>();

        for (ProtocolVersion version : ProtocolVersion.values()) {
            supportedCiphersuites.addAll(getSupportedCipherSuitesFromList(CipherSuite.getImplemented(), version));
        }
        List<ConfigurationFlaw> flawList = new LinkedList<>();
        for (CipherSuite suite : supportedCiphersuites) {
            if (suite.name().contains("EXPORT")) {
                flawList.add(new ConfigurationFlaw("Export Cipher", FlawLevel.SEVERE, "Die Ciphersuite " + suite.name()
                        + " sollte nicht unterstützt werden.", "Deaktivieren sie die Ciphersuite"));
            }
            if (suite.name().contains("RC4")) {
                flawList.add(new ConfigurationFlaw("RC4 Cipher", FlawLevel.MEDIUM, "Die Ciphersuite " + suite.name()
                        + " sollte nicht unterstützt werden.", "Deaktivieren sie die Ciphersuite"));
            }
            if (suite.name().contains("anon")) {
                flawList.add(new ConfigurationFlaw("Anon Cipher", FlawLevel.SEVERE, "Die Ciphersuite " + suite.name()
                        + " sollte nicht unterstützt werden.", "Deaktivieren sie die Ciphersuite"));
            }
            if (suite.name().contains("CBC")) {
                flawList.add(new ConfigurationFlaw("CBC Cipher", FlawLevel.MEDIUM, "Die Ciphersuite " + suite.name()
                        + " sollte nicht unterstützt werden.", "Deaktivieren sie die Ciphersuite"));
            }
        }
        if (flawList.isEmpty()) {
            return new TestResult(getTestName(), "false", "" + getTestName() + " bestanden.");
        } else {
            StringBuilder builder = new StringBuilder("Der " + getTestName()
                    + " wurde nicht bestanden. Dies hat die folgenden Gründe: ");
            for (ConfigurationFlaw flaw : flawList) {
                builder.append(flaw.getFlawDescription());
            }
            return new TestResult(getTestName(), "true", builder.toString());
        }

    }

    public List<CipherSuite> getSupportedCipherSuitesFromList(List<CipherSuite> toTestList, ProtocolVersion version) {
        List<CipherSuite> listWeSupport = new LinkedList<>(toTestList);
        List<CipherSuite> supported = new LinkedList<>(toTestList);

        boolean supportsMore = false;
        do {

            TlsConfig config = new TlsConfig();
            config.setSupportedCiphersuites(listWeSupport);
            config.setHighestProtocolVersion(version);
            WorkflowTrace trace = new WorkflowTrace();
            trace.add(new SendAction(new ClientHelloMessage(config)));
            trace.add(new ReceiveAction(new ArbitraryMessage()));
            config.setWorkflowTrace(trace);
            ConfigHandler handler = new ConfigHandler();
            TransportHandler transportHandler = handler.initializeTransportHandler(config);
            TlsContext tlsContext = handler.initializeTlsContext(config);
            WorkflowExecutor workflowExecutor = handler.initializeWorkflowExecutor(transportHandler, tlsContext);
            try {
                workflowExecutor.executeWorkflow();
            } catch (WorkflowExecutionException ex) {
                ex.printStackTrace();
                // TODO
            }
            transportHandler.closeConnection();
            if (trace.getActuallyRecievedHandshakeMessagesOfType(HandshakeMessageType.SERVER_HELLO) != null) {
                supportsMore = true;
                supported.add(tlsContext.getSelectedCipherSuite());
                listWeSupport.remove(tlsContext.getSelectedCipherSuite());

            }
        } while (supportsMore);
        return supported;
    }

}

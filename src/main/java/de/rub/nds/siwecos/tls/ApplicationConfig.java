/**
 *  SIWECOS-TLS-Scanner - A Webservice for the TLS-Scanner Module of TLS-Attacker
 *
 *  Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 */
package de.rub.nds.siwecos.tls;

import de.rub.nds.siwecos.tls.ws.PoolManager;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.ws.rs.core.Application;

@javax.ws.rs.ApplicationPath("/")
public class ApplicationConfig extends Application {

    @Override
    public Set<Class<?>> getClasses() {
        Set<Class<?>> resources = new java.util.HashSet<>();

        addRestResourceClasses(resources);
        return resources;
    }

    static {
        Properties p = new Properties(System.getProperties());
        if (new File("config.txt").exists()) {
            InputStream input = null;
            try {
                input = new FileInputStream("config.txt");
                // load a properties file

                p.load(input);

            } catch (Exception ex) {
                ex.printStackTrace();
            } finally {
                try {
                    input.close();
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
            }
        }
        if (p.containsKey("tlsscanner.probeThreads")) {
            PoolManager.getInstance().setProbeThreads(Integer.parseInt(p.getProperty("tlsscanner.probeThreads")));
        }
        if (p.containsKey("tlsscanner.parallelProbeThreads")) {
            PoolManager.getInstance().setParallelProbeThreads(
                    Integer.parseInt(p.getProperty("tlsscanner.parallelProbeThreads")));

        }
        if (p.containsKey("tlsscanner.parallelScanJobs")) {
            PoolManager.getInstance().setPoolSize(Integer.parseInt(p.getProperty("tlsscanner.parallelScanJobs")));
        }
        if (p.containsKey("tlsscanner.debugMode")) {
            DebugManager.getInstance().setDebugEnabled(Boolean.parseBoolean(p.getProperty("tlsscanner.debugMode")));
        }
        System.out.println("################### WS-TLS ###################");
        System.out
                .println("Properties are defined in a file called config.txt in the tomcat bin folder, or can be set as enviroment Variables");
        System.out.println("tlsscanner.probeThreads=" + PoolManager.getInstance().getProbeThreads());
        System.out.println("tlsscanner.parallelProbeThreads=" + PoolManager.getInstance().getParallelProbeThreads());
        System.out
                .println("tlsscanner.parallelScanJobs=" + PoolManager.getInstance().getService().getMaximumPoolSize());
        System.out.println("tlsscanner.debugMode=" + DebugManager.getInstance().isDebugEnabled());

    }

    /**
     * Do not modify addRestResourceClasses() method. It is automatically
     * populated with all resources defined in the project. If required, comment
     * out calling this method in getClasses().
     */
    private void addRestResourceClasses(Set<Class<?>> resources) {
        resources.add(de.rub.nds.siwecos.tls.ws.ScannerWS.class);
    }

}

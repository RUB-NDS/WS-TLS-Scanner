# WS-TLS-Scanner
WS-TLS-Scanner is a Webservice created by the Chair for Network and Data Security from the Ruhr-University Bochum for the integration of the [TLS-Scanner](https://github.com/RUB-NDS/TLS-Scanner) in the SIWECOS Project. The Webservice scans a provided URL for various TLS misconfigurations and responds with a JSON report.

# Compiling
In order to compile and use WS-TLS-Scanner, you need to have Java installed, as well as [TLS-Attacker](https://github.com/RUB-NDS/TLS-Attacker), [ModifiableVariables](https://github.com/RUB-NDS/ModifiableVariable) and the [TLS-Scanner](https://github.com/RUB-NDS/TLS-Scanner)

```bash
$ cd TLS-Scanner
$ ./mvnw clean package

```

For hints on installing the required libraries checkout the corresponding GitHub repositories.

**Please note:**  *In order to run this tool you need TLS-Attacker 2.3*

# Running
In order to run WS-TLS-Scanner you need to deploy the .war file from the target/ folder to your favourite java application server (eg. Glassfish, Tomcat ...). After that the webservice should be up and running and can be called by sending a POST like
```
{
  "url": "google.de",
  "dangerLevel": 0,
  "callbackurls": [
    "http://127.0.0.1:8080"
  ]
}
```
to
```
http://127.0.0.1:8080/WS-TLS-Scanner-2.0/start
```

or 

```
http://127.0.0.1:8080/start
```
Depending on your application server.

# Results
TLS-Scanner uses the concept of "checks" which are performed after it collected configuration information. A check which results in "true" is consideres a non optimal choice and is an indicator for a pentester for a possible problem.

An example output may look like this:
```json

{
  "name" : "TLS",
  "hasError" : false,
  "errorMessage" : null,
  "score" : 0,
  "tests" : [ {
    "name" : "HTTPS_NO_RESPONSE",
    "hasError" : false,
    "errorMessage" : null,
    "score" : 100,
    "scoreType" : "success",
    "testDetails" : null
  }, {
    "name" : "HTTPS_NOT_SUPPORTED",
    "hasError" : false,
    "errorMessage" : null,
    "score" : 100,
    "scoreType" : "hidden",
    "testDetails" : null
  }, {
    "name" : "CERTIFICATE_EXPIRED",
    "hasError" : false,
    "errorMessage" : null,
    "score" : 100,
    "scoreType" : "success",
    "testDetails" : null
  }, {
    "name" : "CERTIFICATE_NOT_VALID_YET",
    "hasError" : false,
    "errorMessage" : null,
    "score" : 100,
    "scoreType" : "success",
    "testDetails" : null
  }, {
    "name" : "CERTIFICATE_NOT_SENT_BY_SERVER",
    "hasError" : false,
    "errorMessage" : null,
    "score" : 100,
    "scoreType" : "hidden",
    "testDetails" : null
  }, {
    "name" : "CERTIFICATE_WEAK_HASH_FUNCTION",
    "hasError" : false,
    "errorMessage" : null,
    "score" : 100,
    "scoreType" : "success",
    "testDetails" : null
  }, {
    "name" : "CERTIFICATE_WEAK_SIGN_ALGO",
    "hasError" : false,
    "errorMessage" : null,
    "score" : 100,
    "scoreType" : "hidden",
    "testDetails" : null
  }, {
    "name" : "CIPHERSUITE_ANON",
    "hasError" : false,
    "errorMessage" : null,
    "score" : 100,
    "scoreType" : "success",
    "testDetails" : [ {
      "placeholder" : "ANON_SUITES",
      "values" : ""
    } ]
  }, {
    "name" : "CIPHERSUITE_EXPORT",
    "hasError" : false,
    "errorMessage" : null,
    "score" : 100,
    "scoreType" : "success",
    "testDetails" : [ {
      "placeholder" : "EXPORT_SUITES",
      "values" : ""
    } ]
  }, {
    "name" : "CIPHERSUITE_NULL",
    "hasError" : false,
    "errorMessage" : null,
    "score" : 100,
    "scoreType" : "success",
    "testDetails" : [ {
      "placeholder" : "NULL_SUITES",
      "values" : ""
    } ]
  }, {
    "name" : "CIPHERSUITE_RC4",
    "hasError" : false,
    "errorMessage" : null,
    "score" : 100,
    "scoreType" : "success",
    "testDetails" : [ {
      "placeholder" : "RC4_SUITES",
      "values" : ""
    } ]
  }, {
    "name" : "CIPHERSUITEORDER_ENFORCED",
    "hasError" : false,
    "errorMessage" : null,
    "score" : 90,
    "scoreType" : "success",
    "testDetails" : null
  }, {
    "name" : "PROTOCOLVERSION_SSL2",
    "hasError" : false,
    "errorMessage" : null,
    "score" : 100,
    "scoreType" : "success",
    "testDetails" : null
  }, {
    "name" : "PROTOCOLVERSION_SSL3",
    "hasError" : false,
    "errorMessage" : null,
    "score" : 100,
    "scoreType" : "success",
    "testDetails" : null
  }, {
    "name" : "BLEICHENBACHER_VULNERABLE",
    "hasError" : true,
    "errorMessage" : null,
    "score" : 100,
    "scoreType" : "success",
    "testDetails" : null
  }, {
    "name" : "CRIME_VULNERABLE",
    "hasError" : false,
    "errorMessage" : null,
    "score" : 100,
    "scoreType" : "success",
    "testDetails" : null
  }, {
    "name" : "HEARTBLEED_VULNERABLE",
    "hasError" : true,
    "errorMessage" : null,
    "score" : 100,
    "scoreType" : "success",
    "testDetails" : null
  }, {
    "name" : "INVALID_CURVE_EPHEMERAL_VULNERABLE",
    "hasError" : true,
    "errorMessage" : null,
    "score" : 100,
    "scoreType" : "success",
    "testDetails" : null
  }, {
    "name" : "INVALID_CURVE_VULNERABLE",
    "hasError" : true,
    "errorMessage" : null,
    "score" : 100,
    "scoreType" : "success",
    "testDetails" : null
  }, {
    "name" : "PADDING_ORACLE_VULNERABLE",
    "hasError" : true,
    "errorMessage" : null,
    "score" : 100,
    "scoreType" : "success",
    "testDetails" : null
  }, {
    "name" : "POODLE_VULNERABLE",
    "hasError" : false,
    "errorMessage" : null,
    "score" : 100,
    "scoreType" : "success",
    "testDetails" : null
  }, {
    "name" : "TLS_POODLE_VULNERABLE",
    "hasError" : true,
    "errorMessage" : null,
    "score" : 100,
    "scoreType" : "success",
    "testDetails" : null
  }, {
    "name" : "CIPHERSUITE_DES",
    "hasError" : false,
    "errorMessage" : null,
    "score" : 100,
    "scoreType" : "success",
    "testDetails" : [ {
      "placeholder" : "DES_SUITES",
      "values" : ""
    } ]
  }, {
    "name" : "PROTOCOLVERSION_TLS13",
    "hasError" : false,
    "errorMessage" : null,
    "score" : 0,
    "scoreType" : "bonus",
    "testDetails" : null
  }, {
    "name" : "SWEET32_VULNERABLE",
    "hasError" : false,
    "errorMessage" : null,
    "score" : 80,
    "scoreType" : "warning",
    "testDetails" : null
  } ]
}
```


| Check                               | Meaning                                                                  | 
| ----------------------------------- |:------------------------------------------------------------------------:|
| HTTPS_NO_RESPONSE                   | Checks if we get any response on port 443                                |
| HTTPS_NOT_SUPPORTED                 | Checks if the server supports TLS on port 443                            |
| CERTIFICATE_EXPIRED                 | Checks if the Certificate is expired yet                                 |
| CERTIFICATE_NOT_VALID_YET           | Checks if the Certificate is valid yet                                   |
| CERTIFICATE_WEAK_HASH_FUNCTION      | Checks if the Server uses a weak Hash algorithm for its Certificate      |
| CERTIFICATE_WEAK_SIGN_ALGORITHM     | Checks if the Server uses a weak Signature algorithm for its Certificate |
| CERTIFICATE_NOT_SENT_BY_SERVER      | Checks if the Server did send a Certificate at all                       |
| CIPHERSUITE_ANON                    | Checks if the Server has Anon Ciphersuites enabled                       |
| CIPHERSUITE_CBC                     | Checks if the Server has CBC Ciphersuites enabled for TLS 1.0            | 
| CIPHERSUITE_EXPORT                  | Checks if the Server has Export Ciphersuites enabled                     |
| CIPHERSUITE_NULL                    | Checks if the Server has Null Ciphersuites enabled                       |
| CIPHERSUITE_RC4                     | Checks if the Server has RC4 Ciphersuites enabled                        |
| CIPHERSUITEORDER_ENFORCED           | Checks if the Server does not enforce a Ciphersuite ordering             |
| PROTOCOLVERSION_SSL2                | Checks if SSL 2 is enabled                                               |
| PROTOCOLVERSION_SSL3                | Checks if SSL 3 is enabled                                               |
| PROTOCOLVERSION_TLS13               | Checks if the Server supports TLS 1.3                                    |
| BLEICHENBACHER_VULNERABLE           | Checks if the Server is vulnerable to the Bleichenbacher attack (ROBOT)  |
| PADDING_ORACLE_VULNERABLE           | Checks if the Server is vulnerable to the Padding Oracle attack          |
| INVALID_CURVE_VULNERABLE            | Checks if the Server is vulnerable to the Invalid Curve attack           |
| INVALID_CURVE_EPHEMERAL_VULNERABLE  | Checks if the Server is vulnerable to the Ephemeral Invalid Curve attack |
| POODLE_VULNERABLE                   | Checks if the Server is vulnerable to the Poodle attack                  |
| TLS_POODLE_VULNERABLE               | Checks if the Server is vulnerable to the TLS-Poodle attack              |
| CRIME_VULNERABLE                    | Checks if the Server is vulnerable to the CRIME attack                   |
| SWEET32_VULNERABLE                  | Checks if the Server is vulnerable to the SWEET32 attack                 |
| HEARTBLEED_VULNERABLE               | Checks if the Server is vulnerable to the Heartbleed attack              |
| CVE20162107_VULNERABLE              | Checks if the Server is vulnerable to CVE-2016-2107 	                 |




For more information on the interpretation of this output checkout the [TLS-Scanner](https://github.com/RUB-NDS/TLS-Scanner) repository.

# Docker
You can also run WS-TLS-Scanner with Docker. You can build with:
```
docker build . -t tls-scanner
```
You can then run it with:
```
docker run -it --network host tls-scanner
```
The webservice is then reachable under:
```
http://127.0.0.1:8080/start
```

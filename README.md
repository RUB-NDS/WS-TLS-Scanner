# SIWECOS-TLS-Scanner
SIWECOS-TLS-Scanner is a Webservice created by the Chair for Network and Data Security from the Ruhr-University Bochum for the integration of the [TLS-Scanner](https://github.com/RUB-NDS/TLS-Scanner) in the SIWECOS Project. The Webservice scans a provided URL for various TLS misconfigurations and responds with a JSON report.

# Compiling
In order to compile and use SIWECOS-TLS-Scanner, you need to have Java installed, as well as [TLS-Attacker](https://github.com/RUB-NDS/TLS-Attacker) and the [TLS-Scanner](https://github.com/RUB-NDS/TLS-Scanner)

```bash
$ cd TLS-Scanner
$ ./mvnw clean package

```

For hints on installing the required libraries checkout the corresponding GitHub repositories.

**Please note:**  *In order to run this tool you need TLS-Attacker version 2.2*

# Running
WS-TLS-Scanner implements the SIWECOS scanner API according to [siwecos/scannerapi.yaml](https://github.com/SIWECOS/siwecos-core-api/blob/master/Documentation/api/swagger/scannerapi.yaml)

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
    "score" : 0,
    "scoreType" : "critical",
    "testDetails" : null
  }, {
    "name" : "CERTIFICATE_NOT_VALID_YET",
    "hasError" : false,
    "errorMessage" : null,
    "score" : 0,
    "scoreType" : "critical",
    "testDetails" : null
  }, {
    "name" : "CERTIFICATE_NOT_SENT_BY_SERVER",
    "hasError" : false,
    "errorMessage" : null,
    "score" : 0,
    "scoreType" : "critical",
    "testDetails" : null
  }, {
    "name" : "CERTIFICATE_WEAK_HASH_FUNCTION",
    "hasError" : false,
    "errorMessage" : null,
    "score" : 0,
    "scoreType" : "critical",
    "testDetails" : null
  }, {
    "name" : "CERTIFICATE_WEAK_SIGN_ALGO",
    "hasError" : false,
    "errorMessage" : null,
    "score" : 0,
    "scoreType" : "critical",
    "testDetails" : null
  }, {
    "name" : "CIPHERSUITE_ANON",
    "hasError" : false,
    "errorMessage" : null,
    "score" : 0,
    "scoreType" : "critical",
    "testDetails" : [ {
      "placeholder" : "ANON_SUITES",
      "values" : [ "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5", "TLS_DH_anon_WITH_RC4_128_MD5", "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA" ]
    } ]
  }, {
    "name" : "CIPHERSUITE_EXPORT",
    "hasError" : false,
    "errorMessage" : null,
    "score" : 0,
    "scoreType" : "critical",
    "testDetails" : [ {
      "placeholder" : "EXPORT_SUITES",
      "values" : [ "TLS_RSA_EXPORT_WITH_RC4_40_MD5", "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA" ]
    } ]
  }, {
    "name" : "CIPHERSUITE_NULL",
    "hasError" : false,
    "errorMessage" : null,
    "score" : 0,
    "scoreType" : "critical",
    "testDetails" : [ {
      "placeholder" : "NULL_SUITES",
      "values" : [ "TLS_NULL_WITH_NULL_NULL", "TLS_RSA_WITH_NULL_MD5", "TLS_RSA_WITH_NULL_SHA"]
    } ]
  }, {
    "name" : "CIPHERSUITE_RC4",
    "hasError" : false,
    "errorMessage" : null,
    "score" : 30,
    "scoreType" : "warning",
    "testDetails" : [ {
      "placeholder" : "RC4_SUITES",
      "values" : [ "TLS_RSA_EXPORT_WITH_RC4_40_MD5", "TLS_RSA_WITH_RC4_128_MD5", "TLS_RSA_WITH_RC4_128_SHA", "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5"]
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
    "score" : 0,
    "scoreType" : "critical",
    "testDetails" : null
  }, {
    "name" : "PROTOCOLVERSION_SSL3",
    "hasError" : false,
    "errorMessage" : null,
    "score" : 0,
    "scoreType" : "critical",
    "testDetails" : null
  } ]
}
```

# Results
There are currently multiple checks implemented:


| Check                           | Meaning                                                                  	  | 
| ------------------------------- |:-----------------------------------------------------------------------------:|
| CERTIFICATE_EXPIRED             | Checks if the Certificate is expired yet                                	  |
| CERTIFICATE_NOT_VALID_YET       | Checks if the Certificate is valid yet                                   	  |
| CERTIFICATE_WEAK_HASH_FUNCTION  | Checks if the Server uses a weak Hash algorithm for its Certificate      	  |
| CERTIFICATE_WEAK_SIGN_ALGORITHM | Checks if the Server uses a weak Signature algorithm for its Certificate	  |
| CERTIFICATE_NOT_SENT_BY_SERVER  | Checks if the Server did sent a Certificate at all                      	  |
| CIPHERSUITE_ANON                | Checks if the Server has Anon Ciphersuites enabled                       	  |
| CIPHERSUITE_CBC                 | Checks if the Server has CBC Ciphersuites enabled for TLS 1.0            	  | 
| CIPHERSUITE_EXPORT              | Checks if the Server has Export Ciphersuites enabled                    	  |
| CIPHERSUITE_NULL                | Checks if the Server has Null Ciphersuites enabled                       	  |
| CIPHERSUITE_RC4                 | Checks if the Server has RC4 Ciphersuites enabled                       	  |
| CIPHERSUITEORDER_ENFORCED       | Checks if the Server does not enforce a Ciphersuite ordering             	  |
| PROTOCOLVERSION_SSL2            | Checks if SSL 2 is enabled                                               	  |
| PROTOCOLVERSION_SSL3            | Checks if SSL 3 is enabled                                              	  |
| ATTACK_HEARTBLEED               | Checks if the Server is vulnerable to Heartbleed                        	  |
| ATTACK_PADDING                  | Checks if the Server is vulnerable to a Padding_Oracle Attack (BETA)    	  |
| ATTACK_BLEICHENBACHER           | Checks if the Server is vulnerable to the Bleichenbacher Attack (BETA)  	  |
| ATTACK_POODLE			          | Checks if the Server is vulnerable to the Poodle Attack (BETA)           	  |
| ATTACK_TLS_POODLE               | Checks if the Server is vulnerable to the TLS variant of Poolde (BETA)   	  |
| ATTACK_CVE20162107              | Checks if the Server is vulnerable to CVE20162107 (BETA)			y	 	  |
| ATTACK_INVALID_CURVE            | Checks if the Server is vulnerable to the Invalid Curve Attack (BETA)	      |
| ATTACK_INVALID_CURVE_EPHEMERAL  | Checks if the Server is vulnerable to an Ephemeral Invalid Curve Attack(BETA) |




**Please note:**  *A check with a _result_ of true is considered non optimal*


For more information on the interpretation of this output checkout the [TLS-Scanner](https://github.com/RUB-NDS/TLS-Scanner) repository.

**Please note:**  *A check with a _result_ of true is considered non optimal*


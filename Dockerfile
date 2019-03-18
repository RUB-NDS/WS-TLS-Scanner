FROM tomcat:8.5.0-jre8
RUN apt update && apt-get upgrade -y && apt install -y git maven libcurl3-gnutls default-jdk procps
WORKDIR /src
RUN dpkg -l | grep libgnutls
RUN git clone --branch 2.8 https://github.com/RUB-NDS/TLS-Attacker.git
RUN git clone --branch 2.6.1 https://github.com/RUB-NDS/TLS-Scanner.git
RUN git clone --branch develop https://github.com/SIWECOS/WS-TLS-Scanner.git
WORKDIR /src/TLS-Attacker
RUN mvn  -Djdk.net.URLClassPath.disableClassPathURLCheck=true clean install
WORKDIR /src/TLS-Scanner
RUN mvn clean install
WORKDIR /src/WS-TLS-Scanner
RUN git pull
RUN mvn clean install
RUN cp target/WS-TLS-Scanner-*.war /usr/local/tomcat/webapps/ROOT.war
RUN rm /usr/local/tomcat/webapps/ROOT -r -f
EXPOSE 8080

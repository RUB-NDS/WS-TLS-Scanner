FROM tomcat:8.0.21-jre8
RUN apt update && apt-get upgrade -y && apt install -y git maven libgnutls30 libcurl3-gnutls default-jdk
WORKDIR /src
RUN dpkg -l | grep libgnutls
RUN apt-get -y remove --purge libgnutls-deb0-28
RUN git clone https://github.com/RUB-NDS/TLS-Attacker.git
RUN git clone https://github.com/RUB-NDS/TLS-Scanner.git
RUN git clone https://github.com/SIWECOS/WS-TLS-Scanner.git
WORKDIR /src/TLS-Attacker
RUN mvn clean install -DskipTests=true
WORKDIR /src/TLS-Scanner
RUN mvn clean install -DskipTests=true
WORKDIR /src/WS-TLS-Scanner
RUN mvn clean install -DskipTests=true
COPY ./target/WS-TLS-Scanner-*.war /usr/local/tomcat/webapps/ROOT.war
COPY ./target/WS-TLS-Scanner-* /usr/local/tomcat/webapps/ROOT
EXPOSE 80


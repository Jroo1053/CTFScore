FROM geerlingguy/docker-ubuntu2004-ansible

RUN ln -snf /usr/share/zoneinfo/$CONTAINER_TIMEZONE /etc/localtime && echo $CONTAINER_TIMEZONE > /etc/timezone

RUN apt-get -y update && DEBIAN_FRONTED=noninteractive TZ=Europe/London && apt-get -y install apache2 curl gpg gpg-agent

RUN apt-get -y install openssh-server

RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -

RUN echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list

RUN apt-get -y update && DEBIAN_FRONTED=noninteractive TZ=Europe/London

RUN apt-get -y install wazuh-agent


ENTRYPOINT ["/bin/bash", "-c" , "/var/ossec/bin/wazuh-control start && apache2ctl -D FOREGROUND"]

FROM geerlingguy/docker-ubuntu2004-ansible

USER root

RUN ln -snf /usr/share/zoneinfo/$CONTAINER_TIMEZONE /etc/localtime && echo $CONTAINER_TIMEZONE > /etc/timezone

RUN apt-get -y update && DEBIAN_FRONTED=noninteractive TZ=Europe/London && apt-get -y install curl gpg gpg-agent apt-transport-https

RUN apt-get -y update && DEBIAN_FRONTED=noninteractive TZ=Europe/London && apt-get -y install software-properties-common 


RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -

RUN curl -s https://packages.grafana.com/gpg.key | sudo apt-key add -

RUN echo "deb https://packages.grafana.com/oss/deb stable main" | sudo tee -a /etc/apt/sources.list.d/grafana.list


RUN echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list

RUN apt-get -y update && DEBIAN_FRONTED=noninteractive TZ=Europe/London

RUN apt-get -y install wazuh-agent

RUN apt-get -y install grafana=8.2.5


ENTRYPOINT [ "/bin/bash", ""]
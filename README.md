# Qualitative CTF Monitoring

## Overview

## Implementation

## Project Status

### Log Aggregator

The log aggregator will collect data from the deployed IDS(s) and translate every IDS alert into an common JSON object that can be fed to the web application component. IDS alerts will be collated either from local sources or from a remote file.

#### Local File Support

In a single node deployment all of the IDS(s) will be deployed on the same node using containers. In order to support this use case, it should be possible for the log aggregator to collect data from a local source. The log aggregator should then be able to collect alerts from the other containers using a container volume eg. a Docker volume or  Kubernetes PV.

#### Remote File Support

The log aggregator should also have some capability to collect file from remote sources via SSH. This would allow one deployment of the aggregator to manage data from multiple different IDS deployments which, would be the case in a multi node deployment. This feature will also allow the system to collect events from IDS that cannot be containerised.

Of course, It is also possible to use existing log transport technologies to collect results from remote IDS so that can be read locally. However, existing log transport technology can be difficult to deploy and will often transport the logs without encryption. As a result, it makes sense to allow the log aggregator to connect to nodes via SSH, especially, in a CTF environment were the security of the connected nodes is not of any importance.

#### Basic Configuration

The log aggregator needs to be capable of reading a single config file and responding to the specified changes this, is of particular importance in this case since, as the log aggregator should always being running in an unattended docker container

#### Web API Integration

The log aggregator should be able to make requests to the Web API. 

### Web UI / API

#### Basic Authentication

It would be important to create some level of separation between individual users in the web application for several reasons. First, user accounts would allow IDS events to be tied to individuals rather than the system as a whole which, would provide more accurate scoring to each user by only counting events caused by them. This feature would also help to filter IDS events that are not created by users for example, events created by the log aggregator or other IDS.

#### Event List, Search and Sort

#### Input API

#### IDS Status Feed

#### Scoring Display

### Scoring Algorithm

#### Multi IDS Support

### Infrastructure / Application Packaging

#### Component Containers

#### Ansible Deployment Script

Support for network and single node deployments


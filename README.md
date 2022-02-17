# CTFScore - A Detection Based CTF Assessment Mechanism

![CTFScore Banner](https://ctfresources.s3.eu-west-2.amazonaws.com/bannerhq.png)

## Overview

CTFScore or the "Advanced CTF Scoring System" adds a new dimension to CTFs by, scoring participants on the forensic footprint of their approaches. The system integrates with a [Variety](#supported-ids) of open source IDS and provides real time feedback to users based on the detectability of their attacks.

This allows CTF developers to introduce discussion on defensive methodologies to any CTF and, gives users a reason to explore different attack patterns.

A demo CTF with, the system attached is a available on [TryHackMe.com](https://tryhackme.com/jr/idsevasion). This room walks users through a cyber attack from initial recon to the final post-exploitation task and covers, how the footprint of each attack can be managed.

## Installation

### Architectural Overview

The system consists of two components:

1. The log aggregator - This is a simple Python service that reads from attached IDS alert sources and forwards the results to the second component. 
2. The API/UI - This component handles the majority of the logic and, ingests, scores and stores the alerts that it receives from attached log aggregators. The UI also provides a connivent means to search through IDS alert history and analyse how the attached IDS track exploits

Using this architecture allows the system to serve both a "single node" CTF where, all services are hosted on the same machine and a "multi-node" CTF where, services are split across a LAN (see below). Either, way any installation will require one instance of the API/UI and at least one log aggregator

### Docker

Each component is designed with containerisation in mind, and as a result it is recommended that you use the [provided docker containers]() to integrate the system with your CTF. The docker-compose used to host the public CTF is available [here](), and should be a good starting point for most deployments.

### Ansible

[Ansible plays]() are also available to perform the installation of the demo CTF, and each individual component.

### Manual Deployment

Finally, manual deployment of,course remains an option documentation on this is available [here](https://github.com/Jroo1053/CTFScore/tree/master/Docs#log-aggregator-installation)/

## Configuration

The system does require some configuration work before it can be correctly deployed again, documentation and exemplar config files are available [here](https://github.com/Jroo1053/CTFScore/tree/master/Docs#log-aggregator-installation). In general however, the following is needed:

1. The log aggregator will require:
    1. A path to a valid JSON file containing the target alerts
    2. [JSON pointers](https://github.com/Jroo1053/CTFScore/blob/master/Docs/IDSJSONTable.md) to map the raw JSON to useful data
    3. The URL of the API
    4. Paths to valid API key and auth files
2. The API/UI requires:
    1. A list of all the network assets intended to be targeted during the course of the CTF
    2. Key and ID pairs that match the values set by instances of the log aggregator

### Supported IDS

The current support list is as follows, note that "tentative" support means that, the target IDS will work with the system however, it may not produce expected results as it has not been extensively tested:

| IDS | Support State |
|-----|-------|
| Wazuh | Supported & Tested
| Suricata | Supported & Tested |
| Teler | Tentative Support |

All IDS will require some level of configuration before their events can be ingested by the log aggregator, more info on this is available [here]().

## Licence

This project is licenced under AGPL_3.0.

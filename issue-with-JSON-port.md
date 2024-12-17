## Event Log
```
EDR	{"alert-type": "incident", "created": "2024-12-09T11:57:30.137Z", "computer_id": "1234567891011", "computer_fqdn": "test.local", "computer_name": "test", "detection_name": "This.Malicious.Event", "computer_ip": "74.125.4.161, 177.112.112.18", "severity_score": 36, "incident_id": "67604771d67", "process_path": "/Applications/Microsoft Edge.app", "url": "74.125.4.161", "port": 10500, "source_ip": "192.168.0.10", "severity": "low", "main_action": "blocked"}
```

## Decoder

```xml
<decoder name="EDR">
    <prematch type="pcre2">^EDR\t</prematch>
    <plugin_decoder offset="after_prematch">JSON_Decoder</plugin_decoder>
</decoder>
```

## Rules
```xml
<group name="json,edr">
    <!-- Initial Event Class -->
    <rule id="109000" level="2">
       <decoded_as>EDR</decoded_as>
       <description>EDR Messages</description>
    </rule>
    <!-- Used as a catch all for EDR Events -->
    
    <rule id="109091" level="12">
        <if_sid>109000</if_sid>
        <field name="alert-type">incident</field>
        <description>EDR -  Incident:$(detection_name) Detected on System:$(computer_name) -> Action:$(main_action)</description>
    </rule>
</group>
```

## Rulset Test Output

```
**Phase 1: Completed pre-decoding.
	full event: 'EDR	{"alert-type": "incident", "created": "2024-12-09T11:57:30.137Z", "computer_id": "1234567891011", "computer_fqdn": "test.local", "computer_name": "test", "detection_name": "This.Malicious.Event", "computer_ip": "74.125.4.161, 177.112.112.18", "severity_score": 36, "incident_id": "67604771d67", "process_path": "/Applications/Microsoft Edge.app", "url": "74.125.4.161", "port": 10500, "source_ip": "192.168.0.10", "severity": "low", "main_action": "blocked"}'

**Phase 2: Completed decoding.
	name: 'EDR'
	companyId: '1234'
	computer_fqdn: 'test.local'
	computer_id: '1234567891011'
	computer_ip: '74.125.4.161, 177.112.112.18'
	computer_name: 'test'
	created: '2024-12-09T11:57:30.137Z'
	detection_name: 'This.Malicious.Event'
	incident_id: '67604771d67'
	main_action: 'blocked'
	alert-type: 'incident'
	port: '10500'
	process_path: '/Applications/Microsoft Edge.app'
	severity: 'low'
	severity_score: '36'
	source_ip: '192.168.0.10'
	url: '74.125.4.161'

**Phase 3: Completed filtering (rules).
	id: '109091'
	level: '12'
	description: 'EDR -  Incident:This.Malicious.Event Detected on System:test -> Action:blocked'
	groups: '["json","edr"]'
	firedtimes: '1'
	mail: 'true'
**Alert to be generated.
```

## Behaviour

Alert is generated and notification is sent via our webhook integration
Event is not shown in Wazuh; it is present in alerts.json; 

Filebeat states:
mapper_parsing_exception
object mapping for [data.port] tried to parse a field [port] as object, but found a concrete value

Looking at Wazuh data.port is expecting an Object as referenced in the index mappings:
![image](https://github.com/user-attachments/assets/58b1f372-6745-4050-af67-9e20f5865d49)

## Option 1
Remap the dynamic field in the decoder/rule to map 'port' (which has an integer/string value in event source) to data.port.remote_port

## Option 2 Less Desireable
Pre process the logs in NXlog/Python to change value of port to ["remote_ip":value]

## Option 3 un-desirable 
Change Indicies Mapping in Wazuh to suit; may have impavcts on other event sources. 






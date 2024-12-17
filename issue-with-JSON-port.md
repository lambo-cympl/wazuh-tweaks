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

```

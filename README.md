# OPNSense + CrowdSec + NAXSI WAF Integration
Parsers and scenarios to allow CrowdSec to ban threat actors caught by NAXSI WAF on a OPNSense firewall deployment.
________

**Step 1:** Setup NAXSI WAF on your OPNSense firewall, you can follow this video for guidance:<br> 
[OPNSense - Web Application Firewall (WAF) configuration using NAXSI](https://www.youtube.com/watch?v=IYDoQmUVdvU)

**Step 2:** Install the CrowdSec plugin on your OPNSense firewall (I will be releasing a video about this and subsequent steps soon)

**Step 3:** SSH into your OPNSense firewall head over to the following directory:<br>

```cd /usr/local/etc/crowdsec``` 

**Step 4:** Edit and prepend the following to the top of your acquis.yaml (log acquisition) file:

```
filenames:
    #note: this below will need to point to your web app error log file. 
  - /var/log/nginx/www.dvwa.local.error.log
labels:
  type:  naxsi
 ---
```
**Step 5:** Go to ```cd /usr/local/etc/crowdsec/parsers/s01-parse``` this is where we are going to create the custom parser .yaml file that parses through the NAXSI log file we included above, and matches the Grok pattern in the log. This will save you the efforts of doing this somewhat tedious task yourself.

``` 
name: ls111/opnsense_naxsi_logs
description: "Parse NAXSI error logs on OPNSense firewall"
filter: "evt.Parsed.program == 'naxsi'"
onsuccess: next_stage
nodes:
 - grok:
     pattern: '%{DATESTAMP:timestamp} \[error] %{NUMBER}\#%{NUMBER}: \*%{NUMBER} NAXSI_FMT: ip=%{IPORHOST}&server=%{IPORHOST:serverip}&uri=%{URIPATHPARAM:server_uri}&vers=%{NUMBER}&total_processed=%{NUMBER}&total_blocked=%{NUMBER}&config=block&cscore0=%{DATA}&score0=%{NUMBER:score}&zone0=%{DATA}&id0=%{NUMBER:rule_id}&var_name0=%{DATA}&zone1=%{DATA}&id1=%{NUMBER}&var_name1=%{DATA}, client: %{IPORHOST:source_ip}, server: %{IPORHOST:server_hostname}, request: "%{DATA:request}", host: %{DATA}, referrer: "%{DATA:referrer}"'
     apply_on: message
statics:
  - meta: log_type
    value: waf_attack_event
  - target: evt.StrTime
    expression: evt.Parsed.timestamp
  - meta: source_ip
    expression: evt.Parsed.source_ip
  - meta: http_request
    expression: evt.Parsed.request
  - meta: service
    value: naxsi 
```

**Step 6:** We now have to create the scenario .yaml file in ```cd /usr/local/etc/crowdsec/scenarios``` which takes the parsed log info and determines how CrowdSec should deal with it, in this case we are going to remediate the event by passing the source_ip (attacker ip) over to the firewall bouncer, which will then action the ban.
```
type: trigger
name: ls111/opnsense_naxsi_waf_event
description: "Detects if NAXSI has triggered a security event in accordance with its WAF policies"
filter: evt.Meta.log_type == 'waf_attack_event'
groupby: evt.Meta.source_ip
labels:
  service: naxsi
  type: waf_security_event
  remediation: true
scope:
  type: Ip
  expression: evt.Meta.source_ip
```

**Step 7:** We are now going to edit our profile.yaml file ```/usr/local/etc/crowdsec/profile.yaml``` and change the ban duration to 5 min for lab purposes so that you dont accidently lock yourself out for extended periods, the default for a production environment is 4 hours, but this can be anything you like. The profile controls how we should remediate an attack event and passes the source_ip over to the bouncer which creates the deny rules in PF which is the default firewall OPNSense/BSD uses

```
name: default_ip_remediation
#debug: true
filters:
 - Alert.Remediation == true && Alert.GetScope() == "Ip"
decisions:
 - type: ban
   duration: 5m #duration of the ban set to 5 min, default is 4 hours, changed this for lab purposes.
#duration_expr: Sprintf('%dh', (GetDecisionsCount(Alert.GetValue()) + 1) * 4)
# notifications:
#   - slack_default  # Set the webhook in /usr/local/etc/crowdsec/notifications>
#   - splunk_default # Set the splunk url and token in /usr/local/etc/crowdsec/>
#   - http_default   # Set the required http parameters in /usr/local/etc/crowd>
#   - email_default  # Set the required email parameters in /usr/local/etc/crow>
on_success: break
```

**Step 8:** You need to restart the CrowdSec service: ```service crowdsec restart``` so that all the changes can take effect.

If you attempt to simulate an injection attack against your web app, you will note that NAXSI intercepts this as well as bans the attacker IP address for the duration you specified making the WAF solution more complete.

While OPNSense allows you to install the CrowdSec plugin using the GUI, you can only make partial changes to it using the GUI hence why we need to do everything in shell. CrowdSec comes with its own built in command line tool, access it by typing ```cscli -h``` and you will have full control over your CrowdSec deployment. 

```
cscli is the main command to interact with your crowdsec service, scenarios & db.
It is meant to allow you to manage bans, parsers/scenarios/etc, api and generally manage you crowdsec setup.

Usage:
  cscli [command]

Available Commands:
  alerts        Manage alerts
  bouncers      Manage bouncers [requires local API]
  capi          Manage interaction with Central API (CAPI)
  collections   Manage collections from hub
  completion    Generate completion script
  config        Allows to view current config
  console       Manage interaction with Crowdsec console (https://app.crowdsec.net)
  dashboard     Manage your metabase dashboard container [requires local API]
  decisions     Manage decisions
  explain       Explain log pipeline
  help          Help about any command
  hub           Manage Hub
  hubtest       Run functional tests on hub configurations
  lapi          Manage interaction with Local API (LAPI)
  machines      Manage local API machines [requires local API]
  metrics       Display crowdsec prometheus metrics.
  notifications Helper for notification plugin configuration
  parsers       Install/Remove/Upgrade/Inspect parser(s) from hub
  postoverflows Install/Remove/Upgrade/Inspect postoverflow(s) from hub
  scenarios     Install/Remove/Upgrade/Inspect scenario(s) from hub
  simulation    Manage simulation status of scenarios
  version       Display version and exit.

Flags:
  -c, --config string   path to crowdsec config file (default "/usr/local/etc/crowdsec/config.yaml")
  -o, --output string   Output format : human, json, raw.
      --debug           Set logging to debug.
      --info            Set logging to info.
      --warning         Set logging to warning.
      --error           Set logging to error.
      --trace           Set logging to trace.
  -h, --help            help for cscli
```

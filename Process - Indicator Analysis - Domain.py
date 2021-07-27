"""
This playbook processes domains not in bogon_list and creates a task note for every indicator for review by the analyst
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'check_domain' block
    check_domain(container=container)

    return

def check_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_domain() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.domain", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.destinationDnsDomain", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.sourceDnsDomain", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.src_user_domain", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.url_domain", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.http_referrer_domain", "not in", "custom_list:bogon_list"],
        ],
        logical_operator='or')

    # call connected blocks if condition 1 matched
    if matched:
        domain_filter(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    missing_data_comment(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def domain_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.domain", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.destinationDnsDomain", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.sourceDnsDomain", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.src_user_domain", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.url_domain", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.http_referrer_domain", "not in", "custom_list:bogon_list"],
        ],
        logical_operator='or',
        name="domain_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        merge_domains(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def domain_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_reputation() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'domain_reputation' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['merge_domains:custom_function_result.data.*.item'], action_results=results)

    parameters = []
    
    # build parameters list for 'domain_reputation' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'domain': custom_function_results_item_1[0],
            })

    phantom.act(action="domain reputation", parameters=parameters, assets=['virustotal'], callback=domain_reputation_format, name="domain_reputation")

    return

def generate_task_notes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('generate_task_notes() called')
    
    input_parameter_0 = "Indicator analysis"
    indicator_analysis__analysis = json.loads(phantom.get_run_data(key='indicator_analysis:analysis'))
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['merge_domains:custom_function_result.data.*.item'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='domain_whois_format__as_list')
    formatted_data_2 = phantom.get_format_data(name='domain_reputation_format__as_list')
    formatted_data_3 = phantom.get_format_data(name='domain_hunt_format__as_list')
    formatted_data_4 = phantom.get_format_data(name='domain_intel_format__as_list')
    custom_function_results_item_1_0 = [item[0] for item in custom_function_results_data_1]

    generate_task_notes__note_params = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    """ Maps inputs to processing values and adds debugs for task default template """
    note_params = []
    
    """ Modify for # of notes created per # of indicators example below of 5 means 
        more than 5 indicators found will produce 1 note vs 5 notes. For a maximum of 20 indicators (ip, domain, url, filehash) """
    note_limit = 5
    
    # debug input data
    #phantom.debug("Note Title:")
    #phantom.debug(indicator_analysis__analysis)
    title_data = indicator_analysis__analysis
        
    #phantom.debug("Whois Note:")
    #phantom.debug(formatted_data_1)
    whois_data = formatted_data_1
    
    #phantom.debug("Reputation Note:")
    #phantom.debug(formatted_data_2)
    rep_data = formatted_data_2
    
    #phantom.debug("Hunt Note:")
    #phantom.debug(formatted_data_3)
    hunt_data = formatted_data_3
    
    #phantom.debug("Intelligence Note:")
    #phantom.debug(formatted_data_4)
    intel_data = formatted_data_4
    
    phantom.debug("Processing Indicators")
    #phantom.debug(custom_function_results_data_1)
    indicators = custom_function_results_data_1
    
    # Organize IOCs by value with correct data for note insertion
    for indicator in indicators:
        for title in title_data:
            if indicator[0] in title['indicator']:
                indicator.append(title['title'])
        for whois in whois_data:
            if indicator[0] in whois:
                indicator.append(whois)
        for rep in rep_data:
            if indicator[0] in rep:
                indicator.append(rep)
        for hunt in hunt_data:
            if indicator[0] in hunt:
                indicator.append(hunt)
        for intel in intel_data:
            if indicator[0] in intel:
                indicator.append(intel)
    
    phantom.debug("Reorganzied indicator data for notes.")
    #phantom.debug(indicators)
    
    # Get workbook phase id
    phantom.debug('Getting current phase')

    success, message, phase_id, phase_name = phantom.get_phase()

    phantom.debug(
        'phantom.get_phase results: success: {}, message: {}, phase_id: {}, phase_name: {}'.format(success, message, phase_id, phase_name)
    )
    
    # Task data for adding task notes
    task_data = {}
    
    # Get the tasks for start of the workbook
    for task in phantom.get_tasks(container=container):
        ## gets the current phase and 1st task
        if phase_id == task['data']['phase'] and task['data']['name'] == input_parameter_0:
            task_data.update(task['data'])
            phantom.debug('phantom.get_tasks found the task: task_id: {}, task_name: {}'.format(task_data['id'],task_data['name']))

    """ Create multiple single indicator note or multiple notes (cusotmer defined)
        Change the indicators length to greater than 5 artifacts if you want more notes created
        The maximum number of notes you want created is related to the number of indicators present."""
    
    title = "Automated Domain Indicator Report"
    if len(indicators) <= note_limit:
        # Create loop for creating multiple notes under the same task
        phantom.debug("Found {} indicators.".format(len(indicators)))
        phantom.debug("Creating Multiple indicator notes.")
        for indicator in indicators: 
            title = indicator[1].encode('UTF-8')
            # Define Note content build here
            note_content = "{}\n {}\n {}\n {}".format(indicator[5].encode('UTF-8'),indicator[4].encode('UTF-8'),indicator[3].encode('UTF-8'),indicator[2].encode('UTF-8'))
            #phantom.debug("Multi-Note content: \n {}".format(note_content))
        
            # Build note parameters
            note_params.append({
                "note_type": "task",
                "task_id": task_data['id'],
                "container_id": container['id'],
                "title": title,
                "content": note_content,
                "note_format": "markdown",
                "phase_id": phase_id
            })
    else:
        phantom.debug("Found {} indicators.".format(len(indicators)))
        phantom.debug("Creating Single indicator notes.")
        note_content = ""
        for indicator in indicators: 
            # Define Note content build here
            note_content += "## {}\n {}\n {}\n {}\n {}\n".format(indicator[1].encode('UTF-8'),indicator[5].encode('UTF-8'),indicator[4].encode('UTF-8'),indicator[3].encode('UTF-8'),indicator[2].encode('UTF-8'))
            #phantom.debug("Single Note content: \n {}".format(note_content))

        # Build note parameters
        note_params.append({
            "note_type": "task",
            "task_id": task_data['id'],
            "container_id": container['id'],
            "title": title,
            "content": note_content,
            "note_format": "markdown",
            "phase_id": phase_id
        })    
        
    # Save parameters for REST calls to update
    #phantom.debug("Debug Parameters:")
    generate_task_notes__note_params = note_params

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='generate_task_notes:note_params', value=json.dumps(generate_task_notes__note_params))
    create_task_notes(container=container)

    return

def domain_whois_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_whois_format() called')
    
    template = """%%
### Whois Registration of {0} : *Updated Date: {1}*

- Registrar: {2}
- Expiration: {3}
- Creation: {4}

----
%%"""

    # parameter list for template variable replacement
    parameters = [
        "whois_domain:action_result.parameter.domain",
        "whois_domain:action_result.data.*.updated_date",
        "whois_domain:action_result.data.*.registrar",
        "whois_domain:action_result.data.*.expiration_date",
        "whois_domain:action_result.data.*.creation_date",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="domain_whois_format")

    join_indicator_analysis(container=container)

    return

def whois_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('whois_domain() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'whois_domain' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['merge_domains:custom_function_result.data.*.item'], action_results=results)

    parameters = []
    
    # build parameters list for 'whois_domain' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'domain': custom_function_results_item_1[0],
            })

    phantom.act(action="whois domain", parameters=parameters, assets=['whois'], callback=domain_whois_format, name="whois_domain")

    return

def domain_reputation_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_reputation_format() called')
    
    template = """%%
### VirusTotal Summary of {0}: * {1}, {2}*

*VTI link: https://www.virustotal.com/gui/domain/{0}* 

| Category | Context |
| --- | --- | 
| Category |  {3} | 
| Alexa domain info | {4} |
| Alexa rank | {5} |
| TrendMicro category | {6} |
| BitDefender category | {7} |
| Forcepoint ThreatSeeker category | {8} | 
| Websense ThreatSeeker category | {9} | 
| Opera domain info | {10} |

** WHOIS: **

{11}

---
%%"""

    # parameter list for template variable replacement
    parameters = [
        "domain_reputation:action_result.parameter.domain",
        "domain_reputation:action_result.message",
        "domain_reputation:action_result.data.*.verbose_msg",
        "domain_reputation:action_result.data.*.categories",
        "domain_reputation:action_result.data.*.Alexa domain info",
        "domain_reputation:action_result.data.*.Alexa rank",
        "domain_reputation:action_result.data.*.TrendMicro category",
        "domain_reputation:action_result.data.*.BitDefender category",
        "domain_reputation:action_result.data.*.Forcepoint ThreatSeeker category",
        "domain_reputation:action_result.data.*.Websense ThreatSeeker category",
        "domain_reputation:action_result.data.*.Opera domain info",
        "domain_reputation:action_result.data.*.whois",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="domain_reputation_format")

    join_indicator_analysis(container=container)

    return

def missing_data_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('missing_data_comment() called')

    phantom.comment(container=container, comment="Missing indicator to execute Indicator Analysis - Domain playbook.  Check logic and playbook parameters")

    return

def domain_intelligence(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_intelligence() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'domain_intelligence' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['merge_domains:custom_function_result.data.*.item'], action_results=results)

    parameters = []
    
    # build parameters list for 'domain_intelligence' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'domain': custom_function_results_item_1[0],
            })

    phantom.act(action="domain intelligence", parameters=parameters, assets=['recorded future'], callback=domain_intel_format, name="domain_intelligence")

    return

def domain_intel_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_intel_format() called')
    
    template = """%%
### Recorded Future Summary of {0}: *{1}*
***Critical Label: {2}, Last seen: {3}***

*RF link (Intel Card): {4}*

First Seen: {5}

***Threat List:***
- Threat List: {6}
- Threat list: {7}

***Rules Found***
1.  **{8}** - Evidence: {9}
1. **{10}** - Evidence: {11}
1. ** {12}** - Evidence: {13}
1. ** {14}** - Evidence: {15}
1. **{16}** - Evidence: {17}
1. **{18}** - Evidence: {19}

---
%%"""

    # parameter list for template variable replacement
    parameters = [
        "domain_intelligence:action_result.parameter.domain",
        "domain_intelligence:action_result.summary.riskSummary",
        "domain_intelligence:action_result.summary.criticalityLabel",
        "domain_intelligence:action_result.summary.lastSeen",
        "domain_intelligence:action_result.data.*.intelCard",
        "domain_intelligence:action_result.data.*.timestamps.firstSeen",
        "domain_intelligence:action_result.data.*.threatLists.0.description",
        "domain_intelligence:action_result.data.*.threatLists.1.description",
        "domain_intelligence:action_result.data.*.risk.evidenceDetails.0.rule",
        "domain_intelligence:action_result.data.*.risk.evidenceDetails.0.evidenceString",
        "domain_intelligence:action_result.data.*.risk.evidenceDetails.1.rule",
        "domain_intelligence:action_result.data.*.risk.evidenceDetails.1.evidenceString",
        "domain_intelligence:action_result.data.*.risk.evidenceDetails.2.rule",
        "domain_intelligence:action_result.data.*.risk.evidenceDetails.2.evidenceString",
        "domain_intelligence:action_result.data.*.risk.evidenceDetails.3.rule",
        "domain_intelligence:action_result.data.*.risk.evidenceDetails.3.evidenceString",
        "domain_intelligence:action_result.data.*.risk.evidenceDetails.4.rule",
        "domain_intelligence:action_result.data.*.risk.evidenceDetails.4.evidenceString",
        "domain_intelligence:action_result.data.*.risk.evidenceDetails.5.rule",
        "domain_intelligence:action_result.data.*.risk.evidenceDetails.5.evidenceString",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="domain_intel_format")

    join_indicator_analysis(container=container)

    return

"""
See the doc type in the source code for calculation parameters for this indicator
"""
def indicator_analysis(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('indicator_analysis() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['domain_reputation:action_result.parameter.domain', 'domain_reputation:action_result.summary.downloaded_samples'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['hunt_domain:action_result.parameter.domain', 'hunt_domain:action_result.summary.found', 'hunt_domain:action_result.summary.found_by_verdict_name.malicious'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['domain_intelligence:action_result.parameter.domain', 'domain_intelligence:action_result.data.*.risk.score', 'domain_intelligence:action_result.data.*.risk.criticality'], action_results=results)
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['merge_domains:custom_function_result.data.*.item'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_1_1 = [item[1] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]
    results_item_2_1 = [item[1] for item in results_data_2]
    results_item_2_2 = [item[2] for item in results_data_2]
    results_item_3_0 = [item[0] for item in results_data_3]
    results_item_3_1 = [item[1] for item in results_data_3]
    results_item_3_2 = [item[2] for item in results_data_3]
    custom_function_results_item_1_0 = [item[0] for item in custom_function_results_data_1]

    indicator_analysis__analysis = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Debug data inputs 
    
    #phantom.debug("IP data)
    #phantom.debug(custom_function_results_data_1)
    indicator = custom_function_results_data_1
    
    #phantom.debug("Reputation data")
    #phantom.debug(results_data_1)
    rep_data = results_data_1
    
    #phantom.debug("Detonated data")
    #phantom.debug(results_data_2)
    hunt_data = results_data_2
    
    #phantom.debug("Intel Risk Data")
    #phantom.debug(results_data_3)
    risk_data = results_data_3
    
    # Prepare objects for finished analysis
    indicator_analysis__analysis = []
    threat_level = {
        'title':"",
        'indicator':"",
        'confidence':"Low",
        'threat':"Low"
        }

    """ Calculations for Intelligence Assessment
    Get the result information and performs the following calculation:

    Threat: Values = "High", "Med", "Low"
    Type of validation from source
        High: VT >5 detected downloaded samples, Hybrid-Analysis Found Domain References >5  AND RF= Very Malicious, Malicious, Risk score >50 OR FEYE Detection
        Med: (VT >5 detected downloaded samples, Hybrid-Analysis Found Domain References >5 AND/OR RF= Unusual, Suspicious, Risk score <50) OR FEYE Detection
        Low: VT >5 detected downloaded samples, Hybrid-Analysis Found Domain References >5 OR RF= Unusual, Suspicious, Risk score <50

    Confidence: Detection on # of sources
        High >2 Sources or Finished Intel
        Med  =2 Sources
        Low  <1 Source
    """
    rep_level = 5
    risk_level = 50
    high_risk = ['Very Malicious','Malicious']
    med_risk = ["Suspicious", 'Unusual']
    
    for item in indicator:
        threat_level['indicator'] = item[0]
        phantom.debug('Analyzing indicator: {}'.format(threat_level['indicator']))
        # Evaluates Reputation data
        for rep in rep_data:
            #phantom.debug(rep)
            #phantom.debug('Indicator found: {} | rep value: {}'.format(rep[0],rep[1]))
            if rep[0] == item[0] and rep[1] >= rep_level:
                threat_level['threat'] = "Medium"
                #phantom.debug('Reputation indicator found: {} | {} and setting threat to {}'.format(rep[0],rep[1],threat_level['threat']))
            #phantom.debug('Reputation analysis update: {} | {} with threat: {} | confidence: {}'.format(rep[0],rep[1],threat_level['threat'],threat_level['confidence']))
            
        for hunt in hunt_data:
            #phantom.debug(detonate)
            #phantom.debug('Indicator found: {} | rep value: {}'.format(rep[0],rep[1]))
            if hunt[0] == item[0] and (hunt[1] >= rep_level or hunt[2] in ['Suspicious']):
                threat_level['threat'] = "Medium"
                threat_level['confidence'] = "Medium"
                #phantom.debug('Hunt Medium indicator found: {} | {} and setting threat to {}'.format(rep[0],rep[1],threat_level['threat']))
            elif hunt[0] == item[0] and hunt[2] in ['Malicious']:
                threat_level['threat'] = "High"
                threat_level['confidence'] = "Medium"
                #phantom.debug('Hunt High indicator found: {} | {} and setting threat to {}'.format(rep[0],rep[1],threat_level['threat']))
            #phantom.debug('Hunt analysis update: {} | {} with threat: {} | confidence: {}'.format(rep[0],rep[1],threat_level['threat'],threat_level['confidence']))
                
        # Evaluate risk score or label
        for risk in risk_data:
            # Evaluates Risk Score
            #phantom.debug(risk)
            if risk[0] == item[0] and risk[1] > risk_level:
                if threat_level['threat'] == "Medium":
                    threat_level['threat'] = "High"
                    threat_level['confidence'] = "High"
                    #phantom.debug('Risk score High found: {} | {} and setting threat to {}'.format(risk[0],risk[1],threat_level['threat']))
            # Evaluates Risk Label
            elif risk[0] == item[0] and risk[2] in high_risk:
                if threat_level['threat'] == "Medium":
                    threat_level['threat'] = "High"
                    threat_level['confidence'] = "High"
                    #phantom.debug('High Risk label High/High found: {} | {} and setting threat to {}'.format(risk[0],risk[2],threat_level['threat']))
                else:
                    threat_level['threat'] = "Medium"
                    threat_level['confidence'] = "Medium"
                    #phantom.debug('Medium Risk Label Medium found: {} | {} and setting threat to {}'.format(risk[0],risk[2],threat_level['threat']))
            elif risk[0] == item[0] and risk[2] in med_risk:
                if threat_level['threat'] == "Low":
                    threat_level['confidence'] = "Medium"
                    #phantom.debug('Medium Risk Low/Medium Label found: {} | {} and setting threat to {}'.format(risk[0],risk[2],threat_level['threat']))
            #phantom.debug('Risk analysis update: {} | {}/{} with threat: {} | confidence {}'.format(risk[0],risk[1],risk[2],threat_level['threat'],threat_level['confidence']))

        # Create title for note
        threat_level['title'] = "Analysis of Indicator: {} | Threat: {} | Confidence: {} ".format(threat_level['indicator'], threat_level['threat'], threat_level['confidence'])
        phantom.debug(threat_level['title'])
        
        # Append output value for integration
        indicator_analysis__analysis.append({
            'title':threat_level['title'],
            'indicator':threat_level['indicator'],
            'confidence':threat_level['confidence'],
            'threat':threat_level['threat']
        })

    #phantom.debug('This is indicator analysis below:')
    #phantom.debug(indicator_analysis__analysis)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='indicator_analysis:analysis', value=json.dumps(indicator_analysis__analysis))
    generate_task_notes(container=container)

    return

def join_indicator_analysis(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_indicator_analysis() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['whois_domain', 'domain_reputation', 'domain_intelligence', 'hunt_domain']):
        
        # call connected block "indicator_analysis"
        indicator_analysis(container=container, handle=handle)
    
    return

def hunt_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('hunt_domain() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'hunt_domain' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['merge_domains:custom_function_result.data.*.item'], action_results=results)

    parameters = []
    
    # build parameters list for 'hunt_domain' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'domain': custom_function_results_item_1[0],
            })

    phantom.act(action="hunt domain", parameters=parameters, assets=['hybrid-analysis-personal'], callback=domain_hunt_format, name="hunt_domain")

    return

def domain_hunt_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_hunt_format() called')
    
    template = """%%
### Falcon Sandbox Summary of {0}: *{1}*

*Hybrid Analysis Link: https://www.hybrid-analysis.com/search?query={0}*
- Malicious: {2}
- Suspicious: {3}
- Unknown: {4}
- No Verdict: {5}
- No Specific Threat: {6}
- Allow listed: {7}

---
%%"""

    # parameter list for template variable replacement
    parameters = [
        "hunt_domain:action_result.parameter.domain",
        "hunt_domain:action_result.message",
        "hunt_domain:action_result.summary.found_by_verdict_name.malicious",
        "hunt_domain:action_result.summary.found_by_verdict_name.suspicious",
        "hunt_domain:action_result.summary.found_by_verdict_name.unknown",
        "hunt_domain:action_result.summary.found_by_verdict_name.no_verdict",
        "hunt_domain:action_result.summary.found_by_verdict_name.no_specific_threat",
        "hunt_domain:action_result.summary.found_by_verdict_name.whitelisted",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="domain_hunt_format")

    join_indicator_analysis(container=container)

    return

def set_status_to_new(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_to_new() called')

    phantom.set_status(container=container, status="New")

    return

"""
Customized the block with a for loop to loop thru the created notes parameters.

custom code:
    # build parameters list for 'create_task_notes' call
    for note_params in generate_task_notes__note_params:
        parameters.append({
            'body': json.dumps(note_params),
            'headers': "",
            'location': "/note/",
            'verify_certificate': False,
        })
"""
def create_task_notes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_task_notes() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    generate_task_notes__note_params = json.loads(phantom.get_run_data(key='generate_task_notes:note_params'))
    # collect data for 'create_task_notes' call

    parameters = []
    
    # build parameters list for 'create_task_notes' call
    for note_params in generate_task_notes__note_params:
        parameters.append({
            'location': "/note/",
            'body': json.dumps(note_params),
            'headers': "",
            'verify_certificate': False,
        })

    phantom.act(action="post data", parameters=parameters, assets=['phantom_rest_api'], callback=set_status_to_new, name="create_task_notes")

    return

def merge_domains(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('merge_domains() called')
    
    filtered_artifacts_data_0 = phantom.collect2(container=container, datapath=['filtered-data:domain_filter:condition_1:artifact:*.cef.domain', 'filtered-data:domain_filter:condition_1:artifact:*.cef.destinationDnsDomain', 'filtered-data:domain_filter:condition_1:artifact:*.cef.sourceDnsDomain', 'filtered-data:domain_filter:condition_1:artifact:*.cef.src_user_domain', 'filtered-data:domain_filter:condition_1:artifact:*.cef.url_domain', 'filtered-data:domain_filter:condition_1:artifact:*.cef.http_referrer_domain'])

    parameters = []

    filtered_artifacts_data_0_0 = [item[0] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_1 = [item[1] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_2 = [item[2] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_3 = [item[3] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_4 = [item[4] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_5 = [item[5] for item in filtered_artifacts_data_0]

    parameters.append({
        'input_1': filtered_artifacts_data_0_0,
        'input_2': filtered_artifacts_data_0_1,
        'input_3': filtered_artifacts_data_0_2,
        'input_4': filtered_artifacts_data_0_3,
        'input_5': filtered_artifacts_data_0_4,
        'input_6': filtered_artifacts_data_0_5,
        'input_7': None,
        'input_8': None,
        'input_9': None,
        'input_10': None,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "enrichment/list_merge_dedup", returns the custom_function_run_id
    phantom.custom_function(custom_function='enrichment/list_merge_dedup', parameters=parameters, name='merge_domains', callback=merge_domains_callback)

    return

def merge_domains_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('merge_domains_callback() called')
    
    whois_domain(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    domain_reputation(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    hunt_domain(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    domain_intelligence(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return
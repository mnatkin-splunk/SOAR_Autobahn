"""
This playbook processes URLs not in bogon_list and creates a task note for every indicator for review by the analyst
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'check_urls' block
    check_urls(container=container)

    return

def check_urls(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_urls() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""],
            ["artifact:*.cef.url", "!=", ""],
            ["artifact:*.cef.http_referrer", "==", ""],
        ],
        logical_operator='or')

    # call connected blocks if condition 1 matched
    if matched:
        url_filter(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    missing_data_comment(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def url_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('url_filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.url", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.http_referrer", "==", "custom_list:bogon_list"],
        ],
        logical_operator='or',
        name="url_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        merge_urls(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def url_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('url_reputation() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'url_reputation' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['merge_urls:custom_function_result.data.*.item'], action_results=results)

    parameters = []
    
    # build parameters list for 'url_reputation' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'url': custom_function_results_item_1[0],
            })

    phantom.act(action="url reputation", parameters=parameters, assets=['virustotal'], callback=url_reputation_format, name="url_reputation")

    return

def url_intelligence(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('url_intelligence() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'url_intelligence' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['merge_urls:custom_function_result.data.*.item'], action_results=results)

    parameters = []
    
    # build parameters list for 'url_intelligence' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'url': custom_function_results_item_1[0],
            })

    phantom.act(action="url intelligence", parameters=parameters, assets=['recorded future'], callback=url_intel_format, name="url_intelligence")

    return

"""
Param 0 = Name of the task to update
"""
def generate_task_notes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('generate_task_notes() called')
    
    input_parameter_0 = "Indicator analysis"
    indicator_analysis__analysis = json.loads(phantom.get_run_data(key='indicator_analysis:analysis'))
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['merge_urls:custom_function_result.data.*.item'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='url_reputation_format__as_list')
    formatted_data_2 = phantom.get_format_data(name='url_hunt_format__as_list')
    formatted_data_3 = phantom.get_format_data(name='url_intel_format__as_list')
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
    
    # Debug input data
    #phantom.debug("Task Title:")
    #phantom.debug(indicator_analysis__analysis)
    title_data = indicator_analysis__analysis
        
    #phantom.debug("Reputation Note:")
    #phantom.debug(formatted_data_1)
    rep_data = formatted_data_1
    
    #phantom.debug("Hunt Note:")
    #phantom.debug(formatted_data_2)
    hunt_data = formatted_data_2
    
    #phantom.debug("Intelligence Note:")
    #phantom.debug(formatted_data_3)
    intel_data = formatted_data_3

    #phantom.debug("Indicator Processed")
    #phantom.debug(filtered_artifacts_data_1)
    indicators = custom_function_results_data_1
    
    # Organize Indicators by value with correct data for note insertion
    for indicator in indicators:
        for title in title_data:
            if indicator[0] in title['indicator']:
                indicator.append(title['title'])
        for rep in rep_data:
            if indicator[0] in rep:
                indicator.append(rep)
        for hunt in hunt_data:
            if indicator[0] in hunt:
                indicator.append(hunt)
        for intel in intel_data:
            if indicator[0] in intel:
                indicator.append(intel)

    phantom.debug("Reorganzied note data to indicator.")
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
    
    title = "Automated URL Indicator Report"
    if len(indicators) <= note_limit:
        # Create loop for creating multiple notes under the same task
        phantom.debug("Found {} indicators.".format(len(indicators)))
        phantom.debug("Creating Multiple indicator notes.")
        for indicator in indicators: 
            title = indicator[1].encode('UTF-8')
            # Define Note content build here
            note_content = "{}\n {}\n {}".format(indicator[4].encode('UTF-8'),indicator[3].encode('UTF-8'),indicator[2].encode('UTF-8'))
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
            note_content += "## {}\n {}\n {}\n {}\n".format(indicator[0].encode('UTF-8'),indicator[3].encode('UTF-8'),indicator[2].encode('UTF-8'),indicator[1].encode('UTF-8'))
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

def url_reputation_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('url_reputation_format() called')
    
    template = """%%
### VirusTotal Summary of `{0}`: *{1}, {2}*

*VTI link: {3}*

Scan Date: *{4}*

** Scan Results **

| Scanner | Detected | Result |
| ---- | ---- | ---- |
| Kaspersky | {5} | {6} |
| BitDefender | {7} | {8} | 
| Google Safe Browsing: | {9} | {10} |
| AlienVault | {11} | {12} |
Sophos | {13} | {14} |
| Forcepoint ThreatSeeker: | {15} | {16} |
| ESET |  {17} | {18} |
| MalwareDomainList | {19} | {20} |
| Fortinet | {21} | {22} |

---
%%"""

    # parameter list for template variable replacement
    parameters = [
        "url_reputation:action_result.parameter.url",
        "url_reputation:action_result.message",
        "url_reputation:action_result.data.*.verbose_msg",
        "url_reputation:action_result.data.*.permalink",
        "url_reputation:action_result.data.*.scan_date",
        "url_reputation:action_result.data.*.scans.Kaspersky.detected",
        "url_reputation:action_result.data.*.scans.Kaspersky.result",
        "url_reputation:action_result.data.*.scans.BitDefender.detected",
        "url_reputation:action_result.data.*.scans.BitDefender.result",
        "url_reputation:action_result.data.*.scans.Google Safebrowsing.detected",
        "url_reputation:action_result.data.*.scans.Google Safebrowsing.result",
        "url_reputation:action_result.data.*.scans.AlienVault.detected",
        "url_reputation:action_result.data.*.scans.AlienVault.result",
        "url_reputation:action_result.data.*.scans.Sophos.detected",
        "url_reputation:action_result.data.*.scans.Sophos.result",
        "url_reputation:action_result.data.*.scans.Forcepoint ThreatSeeker.detected",
        "url_reputation:action_result.data.*.scans.Forcepoint ThreatSeeker.result",
        "url_reputation:action_result.data.*.scans.ESET.detected",
        "url_reputation:action_result.data.*.scans.ESET.result",
        "url_reputation:action_result.data.*.scans.MalwareDomainList.detected",
        "url_reputation:action_result.data.*.scans.MalwareDomainList.result",
        "url_reputation:action_result.data.*.scans.Fortinet.detected",
        "url_reputation:action_result.data.*.scans.Fortinet.result",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="url_reputation_format")

    join_indicator_analysis(container=container)

    return

def url_intel_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('url_intel_format() called')
    
    template = """%%
### Recorded Future Summary of `{0}`: *{1}*
***Critical Label: {2}, Last seen: {3}***

*RF link (Intel Card): {4}*

First Seen: {5}

***Threat List:***
- Threat list: {6}
- Threat list: {7}

***Rules Found***
1.  **{8}** - Evidence: {9}
1.  **{10}** - Evidence: {11}
1.  **{12}** - Evidence: {13}
1.  **{14}** - Evidence: {15}
1.  **{16}** - Evidence: {17}
1.  **{18}** - Evidence: {19}

---
%%"""

    # parameter list for template variable replacement
    parameters = [
        "url_intelligence:action_result.parameter.url",
        "url_intelligence:action_result.summary.riskSummary",
        "url_intelligence:action_result.summary.criticalityLabel",
        "url_intelligence:action_result.summary.lastSeen",
        "url_intelligence:action_result.data.*.intelCard",
        "url_intelligence:action_result.data.*.timestamps.firstSeen",
        "url_intelligence:action_result.data.*.threatLists.0.description",
        "url_intelligence:action_result.data.*.threatLists.1.description",
        "url_intelligence:action_result.data.*.risk.evidenceDetails.0.rule",
        "url_intelligence:action_result.data.*.risk.evidenceDetails.0.evidenceString",
        "url_intelligence:action_result.data.*.risk.evidenceDetails.1.rule",
        "url_intelligence:action_result.data.*.risk.evidenceDetails.1.evidenceString",
        "url_intelligence:action_result.data.*.risk.evidenceDetails.2.rule",
        "url_intelligence:action_result.data.*.risk.evidenceDetails.2.evidenceString",
        "url_intelligence:action_result.data.*.risk.evidenceDetails.3.rule",
        "url_intelligence:action_result.data.*.risk.evidenceDetails.3.evidenceString",
        ":url_intelligence:action_result.data.*.risk.evidenceDetails.4.rule",
        "url_intelligence:action_result.data.*.risk.evidenceDetails.4.evidenceString",
        "url_intelligence:action_result.data.*.risk.evidenceDetails.5.rule",
        "url_intelligence:action_result.data.*.risk.evidenceDetails.5.evidenceString",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="url_intel_format")

    join_indicator_analysis(container=container)

    return

def missing_data_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('missing_data_comment() called')

    phantom.comment(container=container, comment="Missing indicator to execute Indicator analysis - URL playbook.  Check logic and playbook parameters")

    return

def hunt_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('hunt_url() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'hunt_url' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['merge_urls:custom_function_result.data.*.item'], action_results=results)

    parameters = []
    
    # build parameters list for 'hunt_url' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'url': custom_function_results_item_1[0],
            })

    phantom.act(action="hunt url", parameters=parameters, assets=['hybrid-analysis-personal'], callback=url_hunt_format, name="hunt_url")

    return

def url_hunt_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('url_hunt_format() called')
    
    template = """%%
### Falcon Sandbox Summary of `{0}`: *{1}, {2} - {3}*
*Hybrid Analysis Link: https://hybrid-analysis.com/sample/{10}*

| Data| Result |
| --- | --- |
| VX family | {4} |
| Scan date | {5} |
| Name(s) | {6} |
| Environment | {7} |
| Type | {8} |
| sha1 | {9} |
| sha256 | {10} |
| Compromised Hosts | {11} |
| Domains | {12} |

---
%%"""

    # parameter list for template variable replacement
    parameters = [
        "hunt_url:action_result.parameter.url",
        "hunt_url:action_result.message",
        "hunt_url:action_result.data.*.verdict",
        "hunt_url:action_result.data.*.threat_score_verbose",
        "hunt_url:action_result.data.*.vx_family",
        "hunt_url:action_result.data.*.analysis_start_time",
        "hunt_url:action_result.data.*.submit_name",
        "hunt_url:action_result.data.*.environment",
        "hunt_url:action_result.data.*.type",
        "hunt_url:action_result.data.*.sha1",
        "hunt_url:action_result.data.*.sha256",
        "hunt_url:action_result.data.*.compromised_hosts",
        "hunt_url:action_result.data.*.domains",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="url_hunt_format")

    join_indicator_analysis(container=container)

    return

"""
See the doc type in the source code for calculation parameters for this indicator
"""
def indicator_analysis(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('indicator_analysis() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['url_reputation:action_result.parameter.url', 'url_reputation:action_result.data.*.positives'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['hunt_url:action_result.parameter.url', 'hunt_url:action_result.data.*.threat_score', 'hunt_url:action_result.data.*.verdict'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['url_intelligence:action_result.parameter.url', 'url_intelligence:action_result.data.*.risk.score', 'url_intelligence:action_result.data.*.risk.criticalityLabel'], action_results=results)
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['merge_urls:custom_function_result.data.*.item'], action_results=results)
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
    
    #phantom.debug("URL data")
    #phantom.debug(custom_function_results_data_1)
    indicator = custom_function_results_data_1
    
    #phantom.debug("Reputation data")
    #phantom.debug(results_data_1)
    rep_data = results_data_1
    
    #phantom.debug("Detonated data")
    #phantom.debug(results_data_2)
    detonate_data = results_data_2
    
    #phantom.debug("Intel data")
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
        High: VT >2 detected downloaded samples, Hybrid-Analysis Threat Score >50  AND RF= Very Malicious, Malicious, Risk score >50 OR FEYE Detection
        Med: (VT >2 detected downloaded samples, Hybrid-Analysis Threat Score >50 AND/OR RF= Unusual, Suspicious, Risk score <50) OR FEYE Detection
        Low: VT >2 detected downloaded samples, Hybrid-Analysis Threat Score >50 OR RF= Unusual, Suspicious, Risk score <50

    Confidence: Detection on # of sources
        High >2 Sources or Finished Intel
        Med  =2 Sources
        Low  <1 Source
    """
    rep_level = 2
    risk_level = 50
    high_risk = ['Very Malicious','Malicious']
    med_risk = ["Suspicious", 'Unusual']
    
    for index, item in enumerate(indicator):
        threat_level['indicator'] = item[0]
        phantom.debug('Analyzing indicator: {} of {}'.format(index,len(indicator)))
        # Evaluates Reputation data
        for rep in rep_data:
            #phantom.debug(rep)
            #phantom.debug('Indicator found: {} | rep value: {}'.format(rep[0],rep[1]))
            if rep[0] == item[0] and rep[1] >= rep_level:
                threat_level['threat'] = "Medium"
                #phantom.debug('Reputation indicator found: {} | {} and setting threat to {}'.format(rep[0],rep[1],threat_level['threat']))
            #phantom.debug('Reputation analysis update: {} | {} with threat: {} | confidence: {}'.format(rep[0],rep[1],threat_level['threat'],threat_level['confidence']))
            
        for detonate in detonate_data:
            #phantom.debug(detonate)
            #phantom.debug('Indicator found: {} | rep value: {}'.format(rep[0],rep[1]))
            if detonate[0] == item[0] and (detonate[1] >= risk_level or detonate[2] in ['Suspicious']):
                threat_level['threat'] = "Medium"
                threat_level['confidence'] = "Medium"
                #phantom.debug('Reputation indicator found: {} | {} and setting threat to {}'.format(rep[0],rep[1],threat_level['threat']))
            elif detonate[0] == item[0] and detonate[2] in ['Malicious']:
                threat_level['threat'] = "High"
                threat_level['confidence'] = "Medium"
                #phantom.debug('Reputation indicator found: {} | {} and setting threat to {}'.format(rep[0],rep[1],threat_level['threat']))
            #phantom.debug('Reputation analysis update: {} | {} with threat: {} | confidence: {}'.format(rep[0],rep[1],threat_level['threat'],threat_level['confidence']))
                
        # Evaluate risk score or label
        for risk in risk_data:
            # Evaluates Risk Score
            #phantom.debug(risk)
            if risk[0] == item[0] and risk[1] > risk_level:
                if threat_level['threat'] == "Medium":
                    threat_level['threat'] = "High"
                    threat_level['confidence'] = "High"
                    #phantom.debug('Risk score found: {} | {} and setting threat to {}'.format(risk[0],risk[1],threat_level['threat']))
            # Evaluates Risk Label
            elif risk[0] == item[0] and risk[2] in high_risk:
                if threat_level['threat'] == "Medium":
                    threat_level['threat'] = "High"
                    threat_level['confidence'] = "High"
                    #phantom.debug('High Risk label found: {} | {} and setting threat to {}'.format(risk[0],risk[2],threat_level['threat']))
                else:
                    threat_level['threat'] = "Medium"
                    threat_level['confidence'] = "Medium"
                    #phantom.debug('Medium Risk Label found: {} | {} and setting threat to {}'.format(risk[0],risk[2],threat_level['threat']))
            elif risk[0] == item[0] and risk[2] in med_risk:
                if threat_level['threat'] == "Low":
                    threat_level['confidence'] = "Medium"
                    #phantom.debug('Medium Risk Label found: {} | {} and setting threat to {}'.format(risk[0],risk[2],threat_level['threat']))
            #phantom.debug('Risk analysis update: {} | {}/{} with threat: {} | confidence {}'.format(risk[0],risk[1],risk[2],threat_level['threat'],threat_level['confidence']))

        # Create title for note
        threat_level['title'] = "Analysis of Indicator: {} | Threat: {} | Confidence: {}".format(threat_level['indicator'], threat_level['threat'], threat_level['confidence'])
        #phantom.debug(threat_level['title'])
        
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
    if phantom.completed(action_names=['url_reputation', 'hunt_url', 'url_intelligence']):
        
        # call connected block "indicator_analysis"
        indicator_analysis(container=container, handle=handle)
    
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

def merge_urls(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('merge_urls() called')
    
    filtered_artifacts_data_0 = phantom.collect2(container=container, datapath=['filtered-data:url_filter:condition_1:artifact:*.cef.requestURL', 'filtered-data:url_filter:condition_1:artifact:*.cef.url', 'filtered-data:url_filter:condition_1:artifact:*.cef.http_referrer'])

    parameters = []

    filtered_artifacts_data_0_0 = [item[0] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_1 = [item[1] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_2 = [item[2] for item in filtered_artifacts_data_0]

    parameters.append({
        'input_1': filtered_artifacts_data_0_0,
        'input_2': filtered_artifacts_data_0_1,
        'input_3': filtered_artifacts_data_0_2,
        'input_4': None,
        'input_5': None,
        'input_6': None,
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
    phantom.custom_function(custom_function='enrichment/list_merge_dedup', parameters=parameters, name='merge_urls', callback=merge_urls_callback)

    return

def merge_urls_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('merge_urls_callback() called')
    
    url_reputation(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    hunt_url(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    url_intelligence(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

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
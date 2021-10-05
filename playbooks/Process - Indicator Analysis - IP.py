"""
This playbook processes IP addresses not in bogon_list and creates a task note for every indicator for review by the analyst
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'check_ip_address' block
    check_ip_address(container=container)

    return

def check_ip_address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_ip_address() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAddress", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.dest_ip", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.sourceAddress", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.src_ip", "not in", "custom_list:bogon_list"],
        ],
        logical_operator='or')

    # call connected blocks if condition 1 matched
    if matched:
        ip_address_filter(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    missing_data_comment(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
TODO:
add sourceAddress to destinationAddress and remove RFC 1918 addresses also
"""
def ip_address_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_address_filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAddress", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.dest_ip", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.sourceAddress", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.src_ip", "not in", "custom_list:bogon_list"],
        ],
        logical_operator='or',
        name="ip_address_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        merge_ip_addresses(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def ip_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_reputation() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'ip_reputation' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['merge_ip_addresses:custom_function_result.data.*.item'], action_results=results)

    parameters = []
    
    # build parameters list for 'ip_reputation' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'ip': custom_function_results_item_1[0],
            })

    phantom.act(action="ip reputation", parameters=parameters, assets=['virustotal'], callback=reputation_format, name="ip_reputation")

    return

def ip_intel(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_intel() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'ip_intel' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['merge_ip_addresses:custom_function_result.data.*.item'], action_results=results)

    parameters = []
    
    # build parameters list for 'ip_intel' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'ip': custom_function_results_item_1[0],
            })

    phantom.act(action="ip intelligence", parameters=parameters, assets=['recorded future'], callback=intel_format, name="ip_intel")

    return

def whois_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('whois_ip() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'whois_ip' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['merge_ip_addresses:custom_function_result.data.*.item'], action_results=results)

    parameters = []
    
    # build parameters list for 'whois_ip' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'ip': custom_function_results_item_1[0],
            })

    phantom.act(action="whois ip", parameters=parameters, assets=['whois'], callback=whois_format, name="whois_ip")

    return

"""
Param 0 = Task to be updated
"""
def generate_task_notes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('generate_task_notes() called')
    
    input_parameter_0 = "Indicator analysis"
    indicator_analysis__analysis = json.loads(phantom.get_run_data(key='indicator_analysis:analysis'))
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['merge_ip_addresses:custom_function_result.data.*.item'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='geolocate_format__as_list')
    formatted_data_2 = phantom.get_format_data(name='whois_format__as_list')
    formatted_data_3 = phantom.get_format_data(name='reputation_format__as_list')
    formatted_data_4 = phantom.get_format_data(name='intel_format__as_list')
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
     
    #phantom.debug("Geolocate results:")
    #phantom.debug(formatted_data_1)
    geo_data = formatted_data_1
    
    #phantom.debug("Whois results:")
    #phantom.debug(formatted_data_2)
    whois_data = formatted_data_2
    
    #phantom.debug("Reputation results:")
    #phantom.debug(formatted_data_3)
    rep_data = formatted_data_3
    
    #phantom.debug("Intel results:")
    #phantom.debug(formatted_data_4)
    intel_data = formatted_data_4

    #phantom.debug("Indicators")
    #phantom.debug(custom_function_results_data_1)
    indicators = custom_function_results_data_1
    
    # Organize indicators by value with correct data for note insertion
    for indicator in indicators:
        for title in title_data:
            if indicator[0] in title['indicator']:
                indicator.append(title['title'])
        for geo in geo_data:
            if indicator[0] in geo:
                indicator.append(geo)
        for whois in whois_data:
            if indicator[0] in whois:
                indicator.append(whois)
        for rep in rep_data:
            if indicator[0] in rep:
                indicator.append(rep)
        for intel in intel_data:
            if indicator[0] in intel:
                indicator.append(intel)
    
    phantom.debug("Reorganzied indicator data for note data.")
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
    
    title = "Automated IP Indicator Report"
    if len(indicators) <= note_limit:
        # Create loop for creating multiple notes under the same task
        phantom.debug("Found {} indicators.".format(len(indicators)))
        phantom.debug("Creating Multiple indicator notes.")
        for indicator in indicators: 
            title = indicator[1]
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

def whois_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('whois_format() called')
    
    template = """%%
### Whois Registration of {0} : *Registered Date: {1}*

{2}

***Latest Registered:***
- Name: {3}
- City: {4}, State: {5}, Country: {6}
- Description: {7}
- Email: {8}
- Updated: {9}

---
%%"""

    # parameter list for template variable replacement
    parameters = [
        "whois_ip:action_result.parameter.ip",
        "whois_ip:action_result.data.*.asn_date",
        "whois_ip:action_result.message",
        "whois_ip:action_result.data.*.nets.0.name",
        "whois_ip:action_result.data.*.nets.0.city",
        "whois_ip:action_result.data.*.nets.0.state",
        "whois_ip:action_result.data.*.nets.0.country",
        "whois_ip:action_result.data.*.nets.0.description",
        "whois_ip:action_result.data.*.nets.0.emails",
        "whois_ip:action_result.data.*.nets.0.updated",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="whois_format")

    join_indicator_analysis(container=container)

    return

def reputation_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('reputation_format() called')
    
    template = """%%
### VirusTotal Summary of {0}: *{1}, {2}*

*VTI link: https://www.virustotal.com/gui/ip-address/{0}*

Network: {3} - Owner: {4}, ASN: {5} 

---
%%"""

    # parameter list for template variable replacement
    parameters = [
        "ip_reputation:action_result.parameter.ip",
        "ip_reputation:action_result.message",
        "ip_reputation:action_result.data.*.verbose_msg",
        "ip_reputation:action_result.data.*.network",
        "ip_reputation:action_result.data.*.as_owner",
        "ip_reputation:action_result.data.*.asn",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="reputation_format")

    join_indicator_analysis(container=container)

    return

def intel_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('intel_format() called')
    
    template = """%%
### Recorded Future Summary of {0}: *{1}*
***Critical Label: {2}, Last seen: {3}***

*RF link (Intel Card): {4}*

Organization: {5} , ASN: {6}, First Seen: {7} 

***Threat List:***
- Threat list: {20}
- Threat list: {21}

***Rules Found***
1. **{8}** - Evidence: {9}
1. **{10}** - Evidence: {11}
1. **{12}** - Evidence: {13}
1. **{14}** - Evidence: {15}
1. **{16}** - Evidence: {17}
1. **{18}** - Evidence: {19}

---
%%"""

    # parameter list for template variable replacement
    parameters = [
        "ip_intel:action_result.parameter.ip",
        "ip_intel:action_result.summary.riskSummary",
        "ip_intel:action_result.summary.criticalityLabel",
        "ip_intel:action_result.summary.lastSeen",
        "ip_intel:action_result.data.*.intelCard",
        "ip_intel:action_result.data.*.location.organization",
        "ip_intel:action_result.data.*.location.asn",
        "ip_intel:action_result.data.*.timestamps.firstSeen",
        "ip_intel:action_result.data.*.risk.evidenceDetails.0.rule",
        "ip_intel:action_result.data.*.risk.evidenceDetails.0.evidenceString",
        "ip_intel:action_result.data.*.risk.evidenceDetails.1.rule",
        "ip_intel:action_result.data.*.risk.evidenceDetails.1.evidenceString",
        "ip_intel:action_result.data.*.risk.evidenceDetails.2.rule",
        "ip_intel:action_result.data.*.risk.evidenceDetails.2.evidenceString",
        "ip_intel:action_result.data.*.risk.evidenceDetails.3.rule",
        "ip_intel:action_result.data.*.risk.evidenceDetails.3.evidenceString",
        "ip_intel:action_result.data.*.risk.evidenceDetails.4.rule",
        "ip_intel:action_result.data.*.risk.evidenceDetails.4.evidenceString",
        "ip_intel:action_result.data.*.risk.evidenceDetails.5.rule",
        "ip_intel:action_result.data.*.risk.evidenceDetails.5.evidenceString",
        "ip_intel:action_result.data.*.threatLists.0.description",
        "ip_intel:action_result.data.*.threatLists.1.description",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="intel_format")

    join_indicator_analysis(container=container)

    return

def geolocation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('geolocation() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'geolocation' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['merge_ip_addresses:custom_function_result.data.*.item'], action_results=results)

    parameters = []
    
    # build parameters list for 'geolocation' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'ip': custom_function_results_item_1[0],
            })

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], callback=geolocate_format, name="geolocation")

    return

def geolocate_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('geolocate_format() called')
    
    template = """%%
### Maxmind Geolocation of {0}: *{1}*, *{2}* 
Latitude: {3} Longitude: {4}

---
%%"""

    # parameter list for template variable replacement
    parameters = [
        "geolocation:action_result.parameter.ip",
        "geolocation:action_result.data.*.continent_name",
        "geolocation:action_result.data.*.country_name",
        "geolocation:action_result.data.*.latitude",
        "geolocation:action_result.data.*.longitude",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="geolocate_format")

    join_indicator_analysis(container=container)

    return

def missing_data_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('missing_data_comment() called')

    phantom.comment(container=container, comment="Missing indicator to execute Indicator Analysis - IP playbook.  Check logic and playbook parameters")

    return

"""
See the doc type in the source code for calculation parameters for this indicator
"""
def indicator_analysis(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('indicator_analysis() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['geolocation:action_result.parameter.ip'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['ip_reputation:action_result.parameter.ip', 'ip_reputation:action_result.summary.downloaded_samples'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['ip_intel:action_result.parameter.ip', 'ip_intel:action_result.data.*.risk.score', 'ip_intel:action_result.data.*.risk.criticalityLabel'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]
    results_item_2_1 = [item[1] for item in results_data_2]
    results_item_3_0 = [item[0] for item in results_data_3]
    results_item_3_1 = [item[1] for item in results_data_3]
    results_item_3_2 = [item[2] for item in results_data_3]

    indicator_analysis__analysis = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Debug data inputs
    #phantom.debug("IP data)
    #phantom.debug(results_data_1)
    indicator = results_data_1
    
    #phantom.debug("IP Reputation data")
    #phantom.debug(results_data_2)
    rep_data = results_data_2
    
    #phantom.debug("IP Intel Risk Data")
    #phantom.debug(results_data_3)
    risk_data = results_data_3
    
    #phantom.debug("IP Finished Intel")
    #phantom.debug(results_data_4)
    #intel_data = results_data_4
    
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
        High: VT >5 detected downloaded samples AND RF= Very Malicious, Malicious, Risk score >50 OR FEYE Detection
        Med: (VT >5 detected downloaded samples AND RF= Unusual, Suspicious, Risk score <50) OR FEYE Detection
        Low: VT >5 detected downloaded samples OR RF= Unusual, Suspicious, Risk score <50

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
                
        # Evaluate risk score or label
        for risk in risk_data:
            # Evaluates Risk Score
            #phantom.debug(risk)
            if risk[0] == item[0] and risk[1] > risk_level:
                if threat_level['threat'] == "Medium":
                    threat_level['threat'] = "High"
                    threat_level['confidence'] = "Medium"
                    #phantom.debug('Risk score found: {} | {} and setting threat to {}'.format(risk[0],risk[1],threat_level['threat']))
            # Evaluates Risk Label
            elif risk[0] == item[0] and risk[2] in high_risk:
                if threat_level['threat'] == "Medium":
                    threat_level['threat'] = "High"
                    threat_level['confidence'] = "Medium"
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
    if phantom.completed(action_names=['geolocation', 'whois_ip', 'ip_reputation', 'ip_intel']):
        
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

def merge_ip_addresses(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('merge_ip_addresses() called')
    
    filtered_artifacts_data_0 = phantom.collect2(container=container, datapath=['filtered-data:ip_address_filter:condition_1:artifact:*.cef.destinationAddress', 'filtered-data:ip_address_filter:condition_1:artifact:*.cef.dest_ip', 'filtered-data:ip_address_filter:condition_1:artifact:*.cef.sourceAddress', 'filtered-data:ip_address_filter:condition_1:artifact:*.cef.src_ip'])

    parameters = []

    filtered_artifacts_data_0_0 = [item[0] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_1 = [item[1] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_2 = [item[2] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_3 = [item[3] for item in filtered_artifacts_data_0]

    parameters.append({
        'input_1': filtered_artifacts_data_0_0,
        'input_2': filtered_artifacts_data_0_1,
        'input_3': filtered_artifacts_data_0_2,
        'input_4': filtered_artifacts_data_0_3,
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
    phantom.custom_function(custom_function='enrichment/list_merge_dedup', parameters=parameters, name='merge_ip_addresses', callback=merge_ip_addresses_callback)

    return

def merge_ip_addresses_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('merge_ip_addresses_callback() called')
    
    geolocation(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    whois_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    ip_reputation(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    ip_intel(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

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
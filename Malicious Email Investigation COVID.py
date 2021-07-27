"""
This playbook investigates and remediates phishing emails with Admin approval.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

"""
This playbook is deigned to perform the investigative steps necessary to investigate a potential Phishing attempt. It will process File attachments, IPs, domains,  and URLs. If there is a positive, the Admin user group on Phantom will have 6 hours to respond to the prompt in order to have the email deleted from the exchange server.
"""

def test_params(container, datapath, key_name):
    params = []
    items = set(phantom.collect(container, datapath, scope='all'))
    for item in items:
        params.append({key_name:item}) 
    return params

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'decision_13' block
    decision_13(container=container)

    # call 'decision_14' block
    decision_14(container=container)

    # call 'decision_15' block
    decision_15(container=container)

    # call 'playbook_local_COVID_19_Indicator_Check_1' block
    playbook_local_COVID_19_Indicator_Check_1(container=container)

    return

def file_reputation_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('file_reputation_2() called')

    # collect data for 'file_reputation_2' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHashMd5', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation_2' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'hash': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("file reputation", parameters=parameters, assets=['virustotal'], callback=decision_7, name="file_reputation_2")

    return

def decision_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_7() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_2:action_result.summary.positives", "<", "3"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        detonate_file_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    join_hunt_file_2(action=action, success=success, container=container, results=results, handle=handle)

    return

def detonate_file_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('detonate_file_2() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'detonate_file_2' call
    inputs_data_1 = phantom.collect2(container=container, datapath=['file_reputation_2:artifact:*.cef.vaultId', 'file_reputation_2:artifact:*.id'], action_results=results)

    parameters = []
    
    # build parameters list for 'detonate_file_2' call
    for inputs_item_1 in inputs_data_1:
        if inputs_item_1[0]:
            parameters.append({
                'file_name': "",
                'vm': "",
                'private': "",
                'vault_id': inputs_item_1[0],
                'playbook': "",
                'force_analysis': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': inputs_item_1[1]},
            })

    phantom.act("detonate file", parameters=parameters, assets=['threatgrid'], callback=decision_8, name="detonate_file_2")

    return

def decision_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_8() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["detonate_file_2:action_result.data.*.threat.score", ">=", 90],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        join_hunt_file_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def hunt_file_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('hunt_file_2() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'hunt_file_2' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHashMd5', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'hunt_file_2' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'hash': container_item[0],
                'range': "0-10",
                'type': "process",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("hunt file", parameters=parameters, assets=['carbon black'], callback=get_system_info_2, name="hunt_file_2")

    return

def join_hunt_file_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_hunt_file_2() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_hunt_file_2_called'):
        return

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'file_reputation_2' ]):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_hunt_file_2_called', value='hunt_file_2')
        
        # call connected block "hunt_file_2"
        hunt_file_2(container=container, handle=handle)
    
    return

def get_system_info_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('get_system_info_2() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_system_info_2' call
    results_data_1 = phantom.collect2(container=container, datapath=['hunt_file_2:action_result.data.*.process.facets.hostname.*.name', 'hunt_file_2:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_system_info_2' call
    for results_item_1 in results_data_1:
        parameters.append({
            'sensor_id': "",
            'ip_hostname': results_item_1[0],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': results_item_1[1]},
        })

    phantom.act("get system info", parameters=parameters, assets=['carbon black'], callback=join_Phishing_Email_Detected, name="get_system_info_2", parent_action=action)

    return

def url_reputation_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('url_reputation_2() called')

    # collect data for 'url_reputation_2' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.requestURL', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'url_reputation_2' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'url': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("url reputation", parameters=parameters, assets=['virustotal'], callback=decision_9, name="url_reputation_2")

    return

def decision_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_9() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["url_reputation_2:action_result.summary.positives", ">=", "3"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        join_get_screenshot_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    detonate_url_2(action=action, success=success, container=container, results=results, handle=handle)

    return

def get_screenshot_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('get_screenshot_2() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_screenshot_2' call
    inputs_data_1 = phantom.collect2(container=container, datapath=['url_reputation_2:artifact:*.cef.requestURL', 'url_reputation_2:artifact:*.id'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_screenshot_2' call
    for inputs_item_1 in inputs_data_1:
        if inputs_item_1[0]:
            parameters.append({
                'url': inputs_item_1[0],
                'size': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': inputs_item_1[1]},
            })

    phantom.act("get screenshot", parameters=parameters, assets=['screenshotmachine'], callback=block_url_1, name="get_screenshot_2")

    return

def join_get_screenshot_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_get_screenshot_2() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_get_screenshot_2_called'):
        return

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'url_reputation_2' ]):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_get_screenshot_2_called', value='get_screenshot_2')
        
        # call connected block "get_screenshot_2"
        get_screenshot_2(container=container, handle=handle)
    
    return

def detonate_url_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('detonate_url_2() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'detonate_url_2' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.requestURL', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'detonate_url_2' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'url': container_item[0],
                'playbook': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("detonate url", parameters=parameters, assets=['threatgrid'], callback=decision_10, name="detonate_url_2")

    return

def decision_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_10() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["detonate_url_2:action_result.data.*.threat.score", ">", 95],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        join_get_screenshot_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def domain_reputation_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('domain_reputation_2() called')

    # collect data for 'domain_reputation_2' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationDnsDomain', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'domain_reputation_2' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'domain': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("domain reputation", parameters=parameters, assets=['virustotal'], callback=decision_11, name="domain_reputation_2")

    return

def decision_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_11() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["domain_reputation_2:action_result.data.*.detected_urls.*.positives", ">=", "3"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        join_Phishing_Email_Detected(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def Phishing_Email_Detected(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Phishing_Email_Detected() called')
    
    # set user and message variables for phantom.prompt call
    user = "Incident Commander"
    message = """An email is being marked as a Phish attempt. Please inspect and approve so that Phantom can delete this instance from your email server. If you do not respond within 6 hours (360 Minutes) the email will _NOT_ be deleted. If you respond \"Yes\" Phantom will start the removal of the phish from all mailboxes on your mail server. All enrichment data is in MIssion Control for your review."""

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No",
                ]
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="Phishing_Email_Detected", response_types=response_types, callback=decision_12)

    return

def join_Phishing_Email_Detected(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_Phishing_Email_Detected() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_Phishing_Email_Detected_called'):
        return

    # check if all connected incoming playbooks or actions are done i.e. have succeeded or failed
    if phantom.completed(playbook_names=['playbook_local_COVID_19_Indicator_Check_1']):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_Phishing_Email_Detected_called', value='Phishing_Email_Detected')
        
        # call connected block "Phishing_Email_Detected"
        Phishing_Email_Detected(container=container, handle=handle)
    
    return

def decision_12(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_12() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Phishing_Email_Detected:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        playbook_local_Delete_Phishing_Email_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def playbook_local_Delete_Phishing_Email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('playbook_local_Delete_Phishing_Email_1() called')
    
    # call playbook "local/Delete Phishing Email", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/Delete Phishing Email", container=container)

    return

def block_url_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('block_url_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'block_url_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_screenshot_2:action_result.parameter.url', 'get_screenshot_2:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'block_url_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'url': results_item_1[0],
                'url_category': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act("block url", parameters=parameters, assets=['zscaler'], callback=join_Phishing_Email_Detected, name="block_url_1", parent_action=action)

    return

def decision_13(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_13() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHashMd5", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        file_reputation_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def decision_14(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_14() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        url_reputation_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def decision_15(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_15() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationDnsDomain", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        domain_reputation_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def playbook_local_COVID_19_Indicator_Check_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('playbook_local_COVID_19_Indicator_Check_1() called')
    
    # call playbook "local/COVID 19 Indicator Check", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/COVID 19 Indicator Check", container=container, name="playbook_local_COVID_19_Indicator_Check_1", callback=decision_16)

    return

def decision_16(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_16() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.covid_related", "==", "yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        Add_COVID_Tag(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def Add_COVID_Tag(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Add_COVID_Tag() called')

    phantom.add_tags(container=container, tags="COVID-19")
    join_Phishing_Email_Detected(container=container)

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all detals of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return
"""
Runs VirusTotal File Detonation Action. Requires to be ran as part of the POV_Malware_Investigation workbook. Needs a vaultId CEF field to be populated. If 25% or more vendors categorise as positive, that will be pinned on the HUD
"""
import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block


# End - Global Code Block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'cf_local_POV_set_event_owner_to_current_1' block
    cf_local_POV_set_event_owner_to_current_1(container=container)

    return

def cf_local_POV_set_event_owner_to_current_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_POV_set_event_owner_to_current_1() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]

    parameters = []

    container_property_0_0 = [item[0] for item in container_property_0]

    parameters.append({
        'container': container_property_0_0,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...



    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/POV_set_event_owner_to_current", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/POV_set_event_owner_to_current', parameters=parameters, name='cf_local_POV_set_event_owner_to_current_1', callback=cf_local_POV_get_current_task_1)

    return

def cf_local_POV_get_current_task_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_POV_get_current_task_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_POV_set_event_owner_to_current_1:custom_function_result.data.currentOwner'], action_results=results )
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]

    parameters = []

    container_property_0_0 = [item[0] for item in container_property_0]
    custom_function_result_0_0 = [item[0] for item in custom_function_result_0]

    parameters.append({
        'container': container_property_0_0,
        'currentOwner': custom_function_result_0_0,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...



    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/POV_get_current_task", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/POV_get_current_task', parameters=parameters, name='cf_local_POV_get_current_task_1', callback=ifSuccess)

    return

"""
If Getting task name and phase sucessful
"""
def ifSuccess(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ifSuccess() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_POV_get_current_task_1:custom_function_result.success", "==", "failed"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        TaskIdentFailure(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    TaskInProgress(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Sets task status to in progress
"""
def TaskInProgress(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('TaskInProgress() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    id_value = container.get('id', None)

    # collect data for 'TaskInProgress' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.task_id', 'cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name'], action_results=results)

    parameters = []
    
    # build parameters list for 'TaskInProgress' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        parameters.append({
            'note': "Task Started",
            'user': "",
            'status': "in progress",
            'role_id': "",
            'task_id': custom_function_results_item_1[0],
            'task_name': "",
            'note_title': custom_function_results_item_1[1],
            'phase_name': "",
            'container_id': id_value,
        })

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], callback=checkForArtifacts, name="TaskInProgress")

    return

"""
VirusTotal File Detonation
"""
def detonateFileVTotal(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('detonateFileVTotal() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'detonateFileVTotal' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.vaultId', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'detonateFileVTotal' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'vault_id': container_item[0],
                'wait_time': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="detonate file", parameters=parameters, assets=['virustotal'], callback=detonateFileVTotal_callback, name="detonateFileVTotal")

    return

def detonateFileVTotal_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('detonateFileVTotal_callback() called')
    
    formatVTFindings(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    cf_local_POV_Percentage_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Ensures we have artifacts with the fileHash field.
"""
def checkForArtifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('checkForArtifacts() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.vaultId", "==", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        TaskCompleteNothingToDo(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    detonateFileVTotal(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Completes task
"""
def TaskCompleteNothingToDo(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('TaskCompleteNothingToDo() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    id_value = container.get('id', None)

    # collect data for 'TaskCompleteNothingToDo' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_set_event_owner_to_current_1:custom_function_result.data.currentOwner'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.task_id', 'cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name'], action_results=results)

    parameters = []
    
    # build parameters list for 'TaskCompleteNothingToDo' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        for custom_function_results_item_2 in custom_function_results_data_2:
            parameters.append({
                'note': "No Artifacts with fileHash field exist.",
                'user': custom_function_results_item_1[0],
                'status': "complete",
                'role_id': "",
                'task_id': custom_function_results_item_2[0],
                'task_name': "",
                'note_title': custom_function_results_item_2[1],
                'phase_name': "",
                'container_id': id_value,
            })

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], name="TaskCompleteNothingToDo")

    return

"""
Formats the results for VT Findings
"""
def formatVTFindings(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('formatVTFindings() called')
    
    template = """##  - Findings ##

# {25} vendors out of {26} determined this as a positive hit.#

## VirusTotal File Detonation Action Results ##

** Summary **

{1}
{2}

|Hash|Permalink|Scan Date|SHA1|SHA256|
|---|---|---|---|---|
|{0}|{3}|{4}|{5}|{6}

### Top Vendor Responses ###

| Vendor | Detected | Result |
|---|---|---|
| CrowdStrike | {7} | {8} |
| Cylance| {9} | {10} |
| ESET| {11} | {12} |
| MalwareBytes | {13} | {14} |
| McAfee | {15} | {16} |
| Mcafee GW | {17} | {18} |
| Microsoft | {19} | {20} |
| Symantec | {21} | {22} |
| Sophos | {23} | {24} |
|---|---|---|"""

    # parameter list for template variable replacement
    parameters = [
        "detonateFileVTotal:action_result.parameter.hash",
        "detonateFileVTotal:action_result.message",
        "detonateFileVTotal:action_result.data.*.verbose_msg",
        "detonateFileVTotal:action_result.data.*.permalink",
        "detonateFileVTotal:action_result.data.*.scan_date",
        "detonateFileVTotal:action_result.data.*.sha1",
        "detonateFileVTotal:action_result.data.*.sha256",
        "detonateFileVTotal:action_result.data.*.scans.CrowdStrike.detected",
        "detonateFileVTotal:action_result.data.*.scans.CrowdStrike.result",
        "detonateFileVTotal:action_result.data.*.scans.Cylance.detected",
        "detonateFileVTotal:action_result.data.*.scans.Cylance.result",
        "detonateFileVTotal:action_result.data.*.scans.ESET-NOD32.detected",
        "detonateFileVTotal:action_result.data.*.scans.ESET-NOD32.result",
        "detonateFileVTotal:action_result.data.*.scans.Malwarebytes.detected",
        "detonateFileVTotal:action_result.data.*.scans.Malwarebytes.result",
        "detonateFileVTotal:action_result.data.*.scans.McAfee.detected",
        "detonateFileVTotal:action_result.data.*.scans.McAfee.result",
        "detonateFileVTotal:action_result.data.*.scans.McAfee-GW-Edition.detected",
        "detonateFileVTotal:action_result.data.*.scans.McAfee-GW-Edition.result",
        "detonateFileVTotal:action_result.data.*.scans.Microsoft.detected",
        "detonateFileVTotal:action_result.data.*.scans.Microsoft.result",
        "detonateFileVTotal:action_result.data.*.scans.Symantec.detected",
        "detonateFileVTotal:action_result.data.*.scans.Symantec.result",
        "detonateFileVTotal:action_result.data.*.scans.Sophos.detected",
        "detonateFileVTotal:action_result.data.*.scans.Sophos.result",
        "detonateFileVTotal:action_result.summary.positives",
        "detonateFileVTotal:action_result.summary.total_scans",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="formatVTFindings")

    addGeneralNote(container=container)

    return

"""
add VT findings to General Notes
"""
def addGeneralNote(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('addGeneralNote() called')

    formatted_data_1 = phantom.get_format_data(name='formatVTFindings')

    note_title = "VirusTotal Summary"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    TaskComplete(container=container)

    return

def cf_local_POV_Percentage_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_POV_Percentage_1() called')
    
    action_results_data_0 = phantom.collect2(container=container, datapath=['detonateFileVTotal:action_result.summary.positives', 'detonateFileVTotal:action_result.summary.total_scans', 'detonateFileVTotal:action_result.parameter.context.artifact_id'], action_results=results )

    parameters = []

    for item0 in action_results_data_0:
        parameters.append({
            'numerator': item0[0],
            'denominator': item0[1],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...



    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/POV_Percentage", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/POV_Percentage', parameters=parameters, name='cf_local_POV_Percentage_1', callback=ifHairStandingUp)

    return

"""
Checks for 25% or more positives rate
"""
def ifHairStandingUp(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ifHairStandingUp() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_POV_Percentage_1:custom_function_result.data.status", "==", "success"],
            ["cf_local_POV_Percentage_1:custom_function_result.data.percentage_val", ">", 24],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        pinHUD(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
If Positives - PIN HUD
"""
def pinHUD(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('pinHUD() called')

    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_Percentage_1:custom_function_result.data.percentage_str'], action_results=results)

    custom_function_results_item_1_0 = [item[0] for item in custom_function_results_data_1]

    phantom.pin(container=container, data=custom_function_results_item_1_0, message="VirusTotal File Detonation Positives", pin_type="card", pin_style="red", name=None)

    return

"""
Completes Task and adds task note.
"""
def TaskComplete(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('TaskComplete() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    id_value = container.get('id', None)

    # collect data for 'TaskComplete' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_set_event_owner_to_current_1:custom_function_result.data.currentOwner'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.task_id', 'cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name'], action_results=results)

    parameters = []
    
    # build parameters list for 'TaskComplete' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        for custom_function_results_item_2 in custom_function_results_data_2:
            parameters.append({
                'note': "Task Completed",
                'user': custom_function_results_item_1[0],
                'status': "complete",
                'role_id': "",
                'task_id': custom_function_results_item_2[0],
                'task_name': "",
                'note_title': custom_function_results_item_2[1],
                'phase_name': "",
                'container_id': id_value,
            })

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], name="TaskComplete")

    return

def TaskIdentFailure(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('TaskIdentFailure() called')

    phantom.comment(container=container, comment="Unable to determined current task. - Please check")

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
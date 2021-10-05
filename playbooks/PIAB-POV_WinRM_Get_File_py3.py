"""
This playbook uses filePath and destinationHostName fields to collect a file using Windows Remote Management. It adds it to the vault and updates the artifact with the vault id.
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
Checks the status of the taskid and phase collection
"""
def ifSuccess(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ifSuccess() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_POV_get_current_task_1:custom_function_result.data.status", "==", "failed"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        TaskIdentError(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    TaskInProgress(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Update Task to in progress
"""
def TaskInProgress(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('TaskInProgress() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    id_value = container.get('id', None)

    # collect data for 'TaskInProgress' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_set_event_owner_to_current_1:custom_function_result.data.currentOwner'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.task_id', 'cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name'], action_results=results)

    parameters = []
    
    # build parameters list for 'TaskInProgress' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        for custom_function_results_item_2 in custom_function_results_data_2:
            parameters.append({
                'note': "Task Started",
                'user': custom_function_results_item_1[0],
                'status': "in progress",
                'role_id': "",
                'task_id': custom_function_results_item_2[0],
                'task_name': "",
                'note_title': custom_function_results_item_2[1],
                'phase_name': "",
                'container_id': id_value,
            })

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], callback=decision_2, name="TaskInProgress")

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.filePath", "==", ""],
            ["artifact:*.cef.destinationHostName", "==", ""],
        ],
        logical_operator='or')

    # call connected blocks if condition 1 matched
    if matched:
        NoArtifactsFound(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    getFile(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
If no artifacts found to work on then update task notes, and complete task. 
"""
def NoArtifactsFound(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('NoArtifactsFound() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    id_value = container.get('id', None)

    # collect data for 'NoArtifactsFound' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_set_event_owner_to_current_1:custom_function_result.data.currentOwner'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.task_id', 'cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name'], action_results=results)

    parameters = []
    
    # build parameters list for 'NoArtifactsFound' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        for custom_function_results_item_2 in custom_function_results_data_2:
            parameters.append({
                'note': "No Artifacts with filePath and/or destinationHostName  exist - Please Check.",
                'user': custom_function_results_item_1[0],
                'status': "complete",
                'role_id': "",
                'task_id': custom_function_results_item_2[0],
                'task_name': "",
                'note_title': custom_function_results_item_2[1],
                'phase_name': "",
                'container_id': id_value,
            })

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], name="NoArtifactsFound")

    return

"""
Uses filePath to fetch file. Hostname (destinationHostname) must be resolvable, and should not be an IP, as Windows Remote Management will baulk.
"""
def getFile(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('getFile() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'getFile' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.filePath', 'artifact:*.cef.destinationHostName', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'getFile' call
    for container_item in container_data:
        if container_item[0] and container_item[1]:
            parameters.append({
                'file_path': container_item[0],
                'ip_hostname': container_item[1],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[2]},
            })

    phantom.act(action="get file", parameters=parameters, assets=['winrm'], callback=IfGetFileSuccess, name="getFile")

    return

"""
Formats the JSON string for update artifact action
"""
def formatCefString(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('formatCefString() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['getFile:action_result.summary.vault_id'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]

    formatCefString__cef_string = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug(results_item_1_0)
    cef_string = '{\"vaultId\":\"' + results_item_1_0[0] + '\"}'
    phantom.debug(cef_string)
    formatCefString__cef_string = cef_string
    ###############################
    ###############################
    ###############################
    ###############################

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='formatCefString:cef_string', value=json.dumps(formatCefString__cef_string))
    updateArtifactVaultId(container=container)

    return

"""
Checks the status of the get file operation
"""
def IfGetFileSuccess(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('IfGetFileSuccess() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["getFile:action_result.status", "==", "failed"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        getFileFailed(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    formatCefString(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    formatGeneralNote(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Update the task with get file failure note, and set task status to incomplete.  
"""
def getFileFailed(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('getFileFailed() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    id_value = container.get('id', None)

    # collect data for 'getFileFailed' call
    results_data_1 = phantom.collect2(container=container, datapath=['getFile:action_result.message', 'getFile:action_result.parameter.context.artifact_id'], action_results=results)
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_set_event_owner_to_current_1:custom_function_result.data.currentOwner'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.task_id', 'cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name'], action_results=results)

    parameters = []
    
    # build parameters list for 'getFileFailed' call
    for results_item_1 in results_data_1:
        for custom_function_results_item_1 in custom_function_results_data_1:
            for custom_function_results_item_2 in custom_function_results_data_2:
                parameters.append({
                    'note': results_item_1[0],
                    'user': custom_function_results_item_1[0],
                    'status': "incomplete",
                    'role_id': "",
                    'task_id': custom_function_results_item_2[0],
                    'task_name': "",
                    'note_title': custom_function_results_item_2[1],
                    'phase_name': "",
                    'container_id': id_value,
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': results_item_1[1]},
                })

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], name="getFileFailed")

    return

"""
Add the VaultId to the artifact for downstream playbooks. 
"""
def updateArtifactVaultId(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('updateArtifactVaultId() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    formatCefString__cef_string = json.loads(phantom.get_run_data(key='formatCefString:cef_string'))
    # collect data for 'updateArtifactVaultId' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.id', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'updateArtifactVaultId' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'cef_json': formatCefString__cef_string,
                'artifact_id': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="update artifact", parameters=parameters, assets=['phantomapp'], name="updateArtifactVaultId")

    return

"""
Formats the text for general note
"""
def formatGeneralNote(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('formatGeneralNote() called')
    
    template = """## {0} - Actions ##

|Hostname|FilePath|Status|Message|VaultId|
|{4}|{5}|{1}|{2}|{3}|{3}"""

    # parameter list for template variable replacement
    parameters = [
        "cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name",
        "getFile:action_result.status",
        "getFile:action_result.message",
        "getFile:action_result.summary.vault_id",
        "getFile:action_result.parameter.ip_hostname",
        "getFile:action_result.parameter.file_path",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="formatGeneralNote")

    GeneralNote(container=container)

    return

"""
Add a note to general notes section
"""
def GeneralNote(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('GeneralNote() called')

    formatted_data_1 = phantom.get_format_data(name='formatGeneralNote')

    note_title = "Get File Notes"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    CompleteTask(container=container)

    return

"""
Updates task to complete. 
"""
def CompleteTask(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('CompleteTask() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    id_value = container.get('id', None)

    # collect data for 'CompleteTask' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_set_event_owner_to_current_1:custom_function_result.data.currentOwner'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.task_id', 'cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='formatGeneralNote')

    parameters = []
    
    # build parameters list for 'CompleteTask' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        for custom_function_results_item_2 in custom_function_results_data_2:
            parameters.append({
                'note': formatted_data_1,
                'user': custom_function_results_item_1[0],
                'status': "complete",
                'role_id': "",
                'task_id': custom_function_results_item_2[0],
                'task_name': "",
                'note_title': custom_function_results_item_2[1],
                'phase_name': "",
                'container_id': id_value,
            })

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], name="CompleteTask")

    return

def TaskIdentError(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('TaskIdentError() called')

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
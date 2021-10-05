"""
Requires the destinationHostName field to exist in artifacts. Then uses that to lookup ActiveDirectory, for system attributes. On success, adds the information to both the artifact, and general notes section.
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
    phantom.custom_function(custom_function='local/POV_get_current_task', parameters=parameters, name='cf_local_POV_get_current_task_1', callback=decision_1)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

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
Unable to determine the task id or current workbook phase.
"""
def TaskIdentError(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('TaskIdentError() called')

    phantom.comment(container=container, comment="Unable to determined current task. - Please check")

    return

"""
Sets the status of the task to InProgress.
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
            ["artifact:*.cef.destinationHostName", "==", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        CompleteTaskNoArtifacts(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    filter_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Completes the task and adds note. Requires artefacts to contain destinationHostName
"""
def CompleteTaskNoArtifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('CompleteTaskNoArtifacts() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    id_value = container.get('id', None)

    # collect data for 'CompleteTaskNoArtifacts' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_set_event_owner_to_current_1:custom_function_result.data.currentOwner'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.task_id', 'cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name'], action_results=results)

    parameters = []
    
    # build parameters list for 'CompleteTaskNoArtifacts' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        for custom_function_results_item_2 in custom_function_results_data_2:
            parameters.append({
                'note': "Unable to find artifacts with destinationHostName field",
                'user': custom_function_results_item_1[0],
                'status': "complete",
                'role_id': "",
                'task_id': custom_function_results_item_2[0],
                'task_name': "",
                'note_title': custom_function_results_item_2[1],
                'phase_name': "",
                'container_id': id_value,
            })

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], name="CompleteTaskNoArtifacts")

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.destinationHostName", "!=", ""],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        getSystemAttrsLDAP(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Use LDAP to lookup any known system attributes of the host itself. (ServicePack, OS, SystemVersion, DNS Hostname)
"""
def getSystemAttrsLDAP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('getSystemAttrsLDAP() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'getSystemAttrsLDAP' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.destinationHostName', 'filtered-data:filter_1:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'getSystemAttrsLDAP' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'fields': "",
                'hostname': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="get system attributes", parameters=parameters, assets=['domainctrl1'], callback=decision_3, name="getSystemAttrsLDAP")

    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["getSystemAttrsLDAP:action_result.status", "==", "failed"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        CompleteTaskError(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    formatCefString(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    formatGeneralNote(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Updates the task to complete and includes the error message received from LDAP
"""
def CompleteTaskError(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('CompleteTaskError() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    id_value = container.get('id', None)

    # collect data for 'CompleteTaskError' call
    results_data_1 = phantom.collect2(container=container, datapath=['getSystemAttrsLDAP:action_result.message', 'getSystemAttrsLDAP:action_result.parameter.context.artifact_id'], action_results=results)
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_set_event_owner_to_current_1:custom_function_result.data.currentOwner'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.task_id', 'cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name'], action_results=results)

    parameters = []
    
    # build parameters list for 'CompleteTaskError' call
    for results_item_1 in results_data_1:
        for custom_function_results_item_1 in custom_function_results_data_1:
            for custom_function_results_item_2 in custom_function_results_data_2:
                parameters.append({
                    'note': results_item_1[0],
                    'user': custom_function_results_item_1[0],
                    'status': "complete",
                    'role_id': "",
                    'task_id': custom_function_results_item_2[0],
                    'task_name': "",
                    'note_title': custom_function_results_item_2[1],
                    'phase_name': "",
                    'container_id': id_value,
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': results_item_1[1]},
                })

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], name="CompleteTaskError")

    return

"""
Formats the output of system attributes into a cef string ready to add the data to the artifact
"""
def formatCefString(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('formatCefString() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['getSystemAttrsLDAP:action_result.data.*.operatingsystem', 'getSystemAttrsLDAP:action_result.data.*.operatingsystemservicepack', 'getSystemAttrsLDAP:action_result.data.*.operatingsystemversion', 'getSystemAttrsLDAP:action_result.data.*.dnshostname'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_1_1 = [item[1] for item in results_data_1]
    results_item_1_2 = [item[2] for item in results_data_1]
    results_item_1_3 = [item[3] for item in results_data_1]

    formatCefString__cef_string = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    status = None
    message = None
    cef_string = None
    
    try:
        cef_string = "{\"cef\":{"
        #cef_string = '{'
        if str(results_item_1_3[0]) != "None":
               #cef_string["dnshostname"] = results_item_1_3[0]
            cef_string = cef_string + '\"dnshostname\":\"' + results_item_1_3[0] + '\"'
                          
        if str(results_item_1_0[0]) != "None":
               #cef_string["operatingsystem"] = results_item_1_0[0]
            cef_string = cef_string + ',\"operatingsystem\":\"' + results_item_1_0[0] + '\"'
        
        if str(results_item_1_2[0]) != "None":
               #cef_string["operatingsystemversion"] = results_item_1_2[0]
            cef_string = cef_string + ',\"operatingsystemversion\":\"' + results_item_1_2[0] + '\"'
                          
        if str(results_item_1_1[0]) != "None":
               #cef_string["operatingsystemservicepack"] = results_item_1_1[0]
            cef_string = cef_string + ',\"operatingsystemservicepack\":\"' + results_item_1_1[0] + '\"'
            
        cef_string = cef_string + '}}'

        phantom.debug('cef_stirng: {}'.format(cef_string))
        status = 'success'

    except Exception as e:
        phantom.error('Failed Creating cef string: {}'.format(e))
        status = 'failed'
        message = e
    
    formatCefString__cef_string = cef_string
    
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='formatCefString:cef_string', value=json.dumps(formatCefString__cef_string))
    updateArtifactLDAP(container=container)

    return

"""
Add OS, Version, ServicePack & DNSHostName if it doesnt exist to the artifact
"""
def updateArtifactLDAP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('updateArtifactLDAP() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    formatCefString__cef_string = json.loads(phantom.get_run_data(key='formatCefString:cef_string'))
    # collect data for 'updateArtifactLDAP' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.id', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'updateArtifactLDAP' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'data': formatCefString__cef_string,
                'overwrite': "",
                'artifact_id': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="update artifact fields", parameters=parameters, assets=['phantomapp'], name="updateArtifactLDAP")

    return

"""
format findings for the LDAP systemInfo lookup ready to add to general notes. 
"""
def formatGeneralNote(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('formatGeneralNote() called')
    
    template = """## {0} - Actions ##

** LDAP Status: **
{1}

|DNS Hostname|Operating System|ServicePack|OS Version|
|---|---|---|---|
| {2} | {3} | {4} | {5} |"""

    # parameter list for template variable replacement
    parameters = [
        "cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name",
        "getSystemAttrsLDAP:action_result.status",
        "getSystemAttrsLDAP:action_result.data.*.dnshostname",
        "getSystemAttrsLDAP:action_result.data.*.operatingsystem",
        "getSystemAttrsLDAP:action_result.data.*.operatingsystemservicepack",
        "getSystemAttrsLDAP:action_result.data.*.operatingsystemversion",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="formatGeneralNote")

    add_note_2(container=container)

    return

def add_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_2() called')

    formatted_data_1 = phantom.get_format_data(name='formatGeneralNote')

    note_title = "LDAP System Info"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    TaskComplete(container=container)

    return

"""
Update task notes and task status to complete. 
"""
def TaskComplete(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('TaskComplete() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    id_value = container.get('id', None)

    # collect data for 'TaskComplete' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_set_event_owner_to_current_1:custom_function_result.data.currentOwner'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.task_id', 'cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='formatGeneralNote')

    parameters = []
    
    # build parameters list for 'TaskComplete' call
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

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], name="TaskComplete")

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
"""
This playbook demonstrates an automated response plan to handling malicious insiders within the environment.
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

def get_user_attributes_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_user_attributes_1() called')

    # collect data for 'get_user_attributes_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceUserName', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_user_attributes_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'fields': "",
                'username': container_item[0],
                'attribute': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="get user attributes", parameters=parameters, assets=['domainctrl1'], callback=format_2, name="get_user_attributes_1")

    return

def reset_password_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('reset_password_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'reset_password_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['disable_user_1:action_result.parameter.username', 'disable_user_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'reset_password_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'username': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="reset password", parameters=parameters, assets=['domainctrl1'], callback=create_ticket_2, name="reset_password_1", parent_action=action)

    return

def create_ticket_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_ticket_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'create_ticket_2' call
    formatted_data_1 = phantom.get_format_data(name='format_2')

    parameters = []
    
    # build parameters list for 'create_ticket_2' call
    parameters.append({
        'table': "",
        'fields': "",
        'vault_id': "",
        'description': formatted_data_1,
        'short_description': "Malicious Insider Flagged - User Disabled and Password Reset",
    })

    phantom.act(action="create ticket", parameters=parameters, assets=['servicenow'], callback=join_set_status_1, name="create_ticket_2", parent_action=action)

    return

def create_ticket_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_ticket_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'create_ticket_1' call
    formatted_data_1 = phantom.get_format_data(name='format_2')

    parameters = []
    
    # build parameters list for 'create_ticket_1' call
    parameters.append({
        'table': "",
        'fields': "",
        'vault_id': "",
        'description': formatted_data_1,
        'short_description': "Malicious Insider Identified - No Action Taken",
    })

    phantom.act(action="create ticket", parameters=parameters, assets=['servicenow'], callback=join_set_status_1, name="create_ticket_1")

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_1:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        disable_user_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    create_ticket_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_1() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """The following user has been flagged as a malicious insider:
{0}

Do you want to proceed with disabling the user and resetting their password? 

Response should be: Yes/No"""

    # parameter list for template variable replacement
    parameters = [
        "get_user_attributes_1:action_result.parameter.username",
    ]

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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_1", parameters=parameters, response_types=response_types, callback=decision_1)

    return

def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_2() called')
    
    template = """The following is a dump of the attributes associated with the malicious user: 
{0}"""

    # parameter list for template variable replacement
    parameters = [
        "get_user_attributes_1:action_result",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_2")

    prompt_1(container=container)

    return

def set_status_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_1() called')

    phantom.set_status(container=container, status="closed")

    return

def join_set_status_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_set_status_1() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_set_status_1_called'):
        return

    # no callbacks to check, call connected block "set_status_1"
    phantom.save_run_data(key='join_set_status_1_called', value='set_status_1', auto=True)

    set_status_1(container=container, handle=handle)
    
    return

def disable_user_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('disable_user_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'disable_user_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_user_attributes_1:action_result.parameter.username', 'get_user_attributes_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'disable_user_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'username': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="disable user", parameters=parameters, assets=['domainctrl1'], callback=reset_password_1, name="disable_user_1")

    return

def Acknowledge_Authorisation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Acknowledge_Authorisation() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Please acknowledge that authorisation has been received from Human Resources, the Employee's Manager or appropriate authority."""

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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="Acknowledge_Authorisation", response_types=response_types, callback=decision_2)

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Acknowledge_Authorisation:action_result.parameter.message", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        return

    # call connected blocks for 'else' condition 2
    add_note_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

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
    phantom.custom_function(custom_function='local/POV_get_current_task', parameters=parameters, name='cf_local_POV_get_current_task_1', callback=decision_3)

    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_POV_get_current_task_1:custom_function_result.data.status", "==", "failed"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        update_task_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    TaskInProgress(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def update_task_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_task_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    id_value = container.get('id', None)

    # collect data for 'update_task_1' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_set_event_owner_to_current_1:custom_function_result.data.username'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.task_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'update_task_1' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        for custom_function_results_item_2 in custom_function_results_data_2:
            parameters.append({
                'note': "",
                'user': custom_function_results_item_1[0],
                'status': "incomplete",
                'role_id': "",
                'task_id': custom_function_results_item_2[0],
                'task_name': "",
                'note_title': "",
                'phase_name': "",
                'container_id': id_value,
            })

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], name="update_task_1")

    return

def TaskInProgress(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('TaskInProgress() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    id_value = container.get('id', None)

    # collect data for 'TaskInProgress' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_set_event_owner_to_current_1:custom_function_result.data.username'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.task_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'TaskInProgress' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        for custom_function_results_item_2 in custom_function_results_data_2:
            parameters.append({
                'note': "",
                'user': custom_function_results_item_1[0],
                'status': "in progress",
                'role_id': "",
                'task_id': custom_function_results_item_2[0],
                'task_name': "",
                'note_title': "",
                'phase_name': "",
                'container_id': id_value,
            })

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], callback=Acknowledge_Authorisation, name="TaskInProgress")

    return

def add_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'add_note_1' call

    parameters = []
    
    # build parameters list for 'add_note_1' call
    parameters.append({
        'title': "Awaiting Authorisation",
        'content': "Authorisation has not yet been received. Waiting.",
        'phase_id': "",
        'container_id': "",
    })

    phantom.act(action="add note", parameters=parameters, assets=['phantomapp'], name="add_note_1")

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
"""
This playbook assigns the event with the current phase first task in the current phase and close out the task as accepted.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'cf_local_POV_set_event_owner_to_current_2' block
    cf_local_POV_set_event_owner_to_current_2(container=container)

    return

def cf_local_POV_set_event_owner_to_current_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_POV_set_event_owner_to_current_2() called')
    
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
    phantom.custom_function(custom_function='local/POV_set_event_owner_to_current', parameters=parameters, name='cf_local_POV_set_event_owner_to_current_2', callback=cf_local_POV_get_current_task_2)

    return

def EventStatusOpen(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('EventStatusOpen() called')

    phantom.set_status(container=container, status="Open")
    updateTaskCompleted(container=container)

    return

def updateTaskInProgress(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('updateTaskInProgress() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    id_value = container.get('id', None)

    # collect data for 'updateTaskInProgress' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_2:custom_function_result.data.current_playbook_name', 'cf_local_POV_get_current_task_2:custom_function_result.data.task_id'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_POV_set_event_owner_to_current_2:custom_function_result.data.currentOwner'], action_results=results)

    parameters = []
    
    # build parameters list for 'updateTaskInProgress' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        for custom_function_results_item_2 in custom_function_results_data_2:
            parameters.append({
                'note': custom_function_results_item_1[0],
                'user': custom_function_results_item_2[0],
                'status': "in progress",
                'role_id': "",
                'task_id': custom_function_results_item_1[1],
                'task_name': "",
                'note_title': "Task Started",
                'phase_name': "",
                'container_id': id_value,
            })

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], callback=EventStatusOpen, name="updateTaskInProgress")

    return

def updateTaskCompleted(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('updateTaskCompleted() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    id_value = container.get('id', None)

    # collect data for 'updateTaskCompleted' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_set_event_owner_to_current_2:custom_function_result.data.currentOwner'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_2:custom_function_result.data.task_id', 'cf_local_POV_get_current_task_2:custom_function_result.data.current_playbook_name'], action_results=results)

    parameters = []
    
    # build parameters list for 'updateTaskCompleted' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        for custom_function_results_item_2 in custom_function_results_data_2:
            parameters.append({
                'note': "Finished - If you need to rerun this playbook - Revert the task status to 'not started' and re run",
                'user': custom_function_results_item_1[0],
                'status': "complete",
                'role_id': "",
                'task_id': custom_function_results_item_2[0],
                'task_name': "",
                'note_title': custom_function_results_item_2[1],
                'phase_name': "",
                'container_id': id_value,
            })

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], name="updateTaskCompleted")

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_POV_get_current_task_2:custom_function_result.data.status", "==", "failed"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        add_comment_4(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    updateTaskInProgress(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def add_comment_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_4() called')

    phantom.comment(container=container, comment="Unable to get tasks for container. - Please check.")

    return

def cf_local_POV_get_current_task_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_POV_get_current_task_2() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_POV_set_event_owner_to_current_2:custom_function_result.data.currentOwner'], action_results=results )
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
    phantom.custom_function(custom_function='local/POV_get_current_task', parameters=parameters, name='cf_local_POV_get_current_task_2', callback=decision_1)

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
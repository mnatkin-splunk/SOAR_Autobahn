"""
Master playbook that runs searches against Splunk SIEM looking for C2, Execution, and Lateral Movement. Add more subplaybooks to extend the capability.
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
    phantom.custom_function(custom_function='local/POV_get_current_task', parameters=parameters, name='cf_local_POV_get_current_task_1', callback=ifError)

    return

"""
Checks the status of the task id and phase
"""
def ifError(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ifError() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_POV_get_current_task_1:custom_function_result.success", "==", "failed"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        TaskIdError(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    TaskInProgress(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def TaskIdError(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('TaskIdError() called')

    phantom.comment(container=container, comment="Unable to determined the task or phase - please check")

    return

"""
Set task status to in progress
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

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], callback=TaskInProgress_callback, name="TaskInProgress")

    return

def TaskInProgress_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('TaskInProgress_callback() called')
    
    playbook_local_PIAB_POV_SIEM_Context_Authentications_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    playbook_local_PIAB_POV_SIEM_Context_C2_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    playbook_local_PIAB_POV_SIEM_Context_Execution_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Use the SIEM to look for authentications and lateral movement.
"""
def playbook_local_PIAB_POV_SIEM_Context_Authentications_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_PIAB_POV_SIEM_Context_Authentications_1() called')
    
    # call playbook "local/PIAB-POV_SIEM_Context_Authentications", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/PIAB-POV_SIEM_Context_Authentications", container=container)
    join_TaskCompleted(container=container)

    return

"""
Use the SIEM to look for evidence of dropper files, or command and control traffic.
"""
def playbook_local_PIAB_POV_SIEM_Context_C2_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_PIAB_POV_SIEM_Context_C2_1() called')
    
    # call playbook "local/PIAB-POV_SIEM_Context_C2", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/PIAB-POV_SIEM_Context_C2", container=container)
    join_TaskCompleted(container=container)

    return

"""
Use the SIEM to look for evidence of execution on the originating host.
"""
def playbook_local_PIAB_POV_SIEM_Context_Execution_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_PIAB_POV_SIEM_Context_Execution_1() called')
    
    # call playbook "local/PIAB-POV_SIEM_Context_Execution", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/PIAB-POV_SIEM_Context_Execution", container=container)
    join_TaskCompleted(container=container)

    return

"""
Update task to completed state
"""
def TaskCompleted(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('TaskCompleted() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    id_value = container.get('id', None)

    # collect data for 'TaskCompleted' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_set_event_owner_to_current_1:custom_function_result.data.currentOwner'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.task_id', 'cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name'], action_results=results)

    parameters = []
    
    # build parameters list for 'TaskCompleted' call
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

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], name="TaskCompleted")

    return

def join_TaskCompleted(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_TaskCompleted() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['TaskInProgress']):
        
        # call connected block "TaskCompleted"
        TaskCompleted(container=container, handle=handle)
    
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
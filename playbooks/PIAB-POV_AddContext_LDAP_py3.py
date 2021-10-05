"""
This Playbook  runs the 2nd task of the  current phase , gets user and host attributes and adds note to the task before closing the task.
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

"""
actual username - filtered-data:filter_CDT_reporter:condition_1:artifact:*.cef.phishing_reporter
"""
def get_user_attributes_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_user_attributes_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_user_attributes_2' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filterPhishReporterArtifact:condition_1:artifact:*.cef.fromEmail', 'filtered-data:filterPhishReporterArtifact:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_user_attributes_2' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'fields': "",
                'username': filtered_artifacts_item_1[0],
                'attribute': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="get user attributes", parameters=parameters, assets=['domainctrl1'], callback=CheckLDAPActionResult, name="get_user_attributes_2")

    return

def formatGeneralNote(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('formatGeneralNote() called')
    
    template = """#  {5} - Findings #

## Get LDAP User Attributes Action ##
** Status: ** {4}

**LDAP Attributes of:** {0}

| Department | Lastlogon | Manager |
|---|---|---|
%%
| {1} | {2} | {3} |
%%"""

    # parameter list for template variable replacement
    parameters = [
        "get_user_attributes_2:action_result.data.*.displayname",
        "get_user_attributes_2:action_result.data.*.department",
        "get_user_attributes_2:action_result.data.*.lastlogon",
        "get_user_attributes_2:action_result.data.*.manager",
        "get_user_attributes_2:action_result.status",
        "cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="formatGeneralNote")

    addTaskNote(container=container)

    return

"""
use task update parameter next_playbook to automatically update the next playbook called.

Custom code:

task_update__next_playbook = json.loads(phantom.get_run_data(key='task_update:next_playbook'))
    
    if task_update__next_playbook:    
        # call playbook "local/Set Priority", returns the playbook_run_id
        playbook_run_id = phantom.playbook(task_update__next_playbook, container=container)
    else:
        phantom.error("No playbook was found in the next task, reverting to manual mode")
"""
def call_next_playbook(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('call_next_playbook() called')
    next_playbook = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.next_playbook'])
    # call playbook "local/Review Indicators", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook=next_playbook, container=container)

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
    phantom.custom_function(custom_function='local/POV_get_current_task', parameters=parameters, name='cf_local_POV_get_current_task_1', callback=ifUpdatedTasksOK)

    return

def TaskInProgress(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('TaskInProgress() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    id_value = container.get('id', None)

    # collect data for 'TaskInProgress' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name', 'cf_local_POV_get_current_task_1:custom_function_result.data.task_id'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_POV_set_event_owner_to_current_1:custom_function_result.data.currentOwner'], action_results=results)

    parameters = []
    
    # build parameters list for 'TaskInProgress' call
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

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], callback=ifArtifactHasPhishingReporterDetail, name="TaskInProgress")

    return

def filterPhishReporterArtifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filterPhishReporterArtifact() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.name", "==", "Phishing Reporter"],
        ],
        name="filterPhishReporterArtifact:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_user_attributes_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        custom_function_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def CheckLDAPActionResult(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('CheckLDAPActionResult() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_user_attributes_2:action_result.status", "==", "failed"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        CommentFailureMessage(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    formatGeneralNote(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def FailedLDAPTaskNote(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('FailedLDAPTaskNote() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    id_value = container.get('id', None)

    # collect data for 'FailedLDAPTaskNote' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_user_attributes_2:action_result.message', 'get_user_attributes_2:action_result.parameter.context.artifact_id'], action_results=results)
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.task_id', 'cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name'], action_results=results)

    parameters = []
    
    # build parameters list for 'FailedLDAPTaskNote' call
    for results_item_1 in results_data_1:
        for custom_function_results_item_1 in custom_function_results_data_1:
            parameters.append({
                'note': results_item_1[0],
                'user': "",
                'status': "complete",
                'role_id': "",
                'task_id': custom_function_results_item_1[0],
                'task_name': "",
                'note_title': custom_function_results_item_1[1],
                'phase_name': "",
                'container_id': id_value,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], name="FailedLDAPTaskNote")

    return

def ifUpdatedTasksOK(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ifUpdatedTasksOK() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_POV_get_current_task_1:custom_function_result.data.status", "==", "failed"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        TaskErrorComment(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    TaskInProgress(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def TaskErrorComment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('TaskErrorComment() called')

    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.message'], action_results=results)

    custom_function_results_item_1_0 = [item[0] for item in custom_function_results_data_1]

    phantom.comment(container=container, comment=custom_function_results_item_1_0)

    return

def ifArtifactHasPhishingReporterDetail(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ifArtifactHasPhishingReporterDetail() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.name", "==", "Phishing Reporter"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        filterPhishReporterArtifact(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    add_comment_6(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def add_comment_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_6() called')

    phantom.comment(container=container, comment="No Phishing Reporter Artifact Found")
    formatNoReporterNote(container=container)

    return

def CommentFailureMessage(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('CommentFailureMessage() called')

    results_data_1 = phantom.collect2(container=container, datapath=['get_user_attributes_2:action_result.message'], action_results=results)

    results_item_1_0 = [item[0] for item in results_data_1]

    phantom.comment(container=container, comment=results_item_1_0)
    FailedLDAPTaskNote(container=container)

    return

"""
Adds findings note to general Notes
"""
def addTaskNote(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('addTaskNote() called')

    formatted_data_1 = phantom.get_format_data(name='formatGeneralNote')

    note_title = "Findings"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    CompleteTask(container=container)

    return

def CompleteTask(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('CompleteTask() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    id_value = container.get('id', None)

    # collect data for 'CompleteTask' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_set_event_owner_to_current_1:custom_function_result.data.currentOwner'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.task_id', 'cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name'], action_results=results)

    parameters = []
    
    # build parameters list for 'CompleteTask' call
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

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], name="CompleteTask")

    return

"""
Create a task note, showing no phishing reporter artifact found.
"""
def formatNoReporterNote(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('formatNoReporterNote() called')
    
    template = """#  {0} - Findings #

** Unable to find 'Phishing Reporter' artifact **

Ensure email has been parsed correctly, or manually add an artifact after discovering who sent the email"""

    # parameter list for template variable replacement
    parameters = [
        "cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="formatNoReporterNote")

    updateTaskNote(container=container)

    return

"""
Add task note, showing no phishing reporter artifact found
"""
def updateTaskNote(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('updateTaskNote() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    id_value = container.get('id', None)

    # collect data for 'updateTaskNote' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_set_event_owner_to_current_1:custom_function_result.data.currentOwner'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.task_id', 'cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='formatNoReporterNote')

    parameters = []
    
    # build parameters list for 'updateTaskNote' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        for custom_function_results_item_2 in custom_function_results_data_2:
            parameters.append({
                'note': formatted_data_1,
                'user': custom_function_results_item_1[0],
                'status': "incomplete",
                'role_id': "",
                'task_id': custom_function_results_item_2[0],
                'task_name': "",
                'note_title': custom_function_results_item_2[1],
                'phase_name': "",
                'container_id': id_value,
            })

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], name="updateTaskNote")

    return

def custom_function_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('custom_function_1() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filterPhishReporterArtifact:condition_1:artifact:*.cef.fromEmail'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug('user: {}'.format(filtered_artifacts_item_1_0))
    #############################################################

    ################################################################################
    ## Custom Code End
    ################################################################################

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
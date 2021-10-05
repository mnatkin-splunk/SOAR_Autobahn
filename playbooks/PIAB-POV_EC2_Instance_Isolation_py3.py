"""
Isolate an EC2 instance by changing its security group in order to protect it from malicious traffic. This playbook can be started alone or used from another playbook after doing investigation and notification. The existing security group is removed from the instance and a new isolation security group is added.
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
    
    # call 'decision_2' block
    decision_2(container=container)

    return

"""
Separate the EC2 resource from the other artifacts in the Finding.
"""
def filter_ec2_resource(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_ec2_resource() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "AwsEc2Instance Resource Artifact"],
        ],
        name="filter_ec2_resource:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        cf_local_POV_set_event_owner_to_current_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Gather EC2 instance metadata before making any changes.
"""
def describe_instance_before(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('describe_instance_before() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'describe_instance_before' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_ec2_resource:condition_1:artifact:*.cef.InstanceId', 'filtered-data:filter_ec2_resource:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'describe_instance_before' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        parameters.append({
            'limit': "",
            'dry_run': "",
            'filters': "",
            'instance_ids': filtered_artifacts_item_1[0],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': filtered_artifacts_item_1[1]},
        })

    phantom.act(action="describe instance", parameters=parameters, assets=['aws_ec2'], callback=add_isolation_SG, name="describe_instance_before")

    return

"""
Add the isolation security group to the EC2 instance.
"""
def add_isolation_SG(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_isolation_SG() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    GetIsolationSecurityGroup__isolationGroup = json.loads(phantom.get_run_data(key='GetIsolationSecurityGroup:isolationGroup'))
    # collect data for 'add_isolation_SG' call
    results_data_1 = phantom.collect2(container=container, datapath=['describe_instance_before:action_result.parameter.instance_ids', 'describe_instance_before:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'add_isolation_SG' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'group_id': GetIsolationSecurityGroup__isolationGroup,
                'instance_id': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="assign instance", parameters=parameters, assets=['aws_ec2'], callback=remove_existing_SGs, name="add_isolation_SG", parent_action=action)

    return

"""
Remove any pre-existing security groups that were part of the insecure configuration.
"""
def remove_existing_SGs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('remove_existing_SGs() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'remove_existing_SGs' call
    results_data_1 = phantom.collect2(container=container, datapath=['describe_instance_before:action_result.data.*.Reservations.*.Instances.*.SecurityGroups.*.GroupId', 'describe_instance_before:action_result.parameter.context.artifact_id'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['add_isolation_SG:action_result.parameter.instance_id', 'add_isolation_SG:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'remove_existing_SGs' call
    for results_item_1 in results_data_1:
        for results_item_2 in results_data_2:
            if results_item_1[0] and results_item_2[0]:
                parameters.append({
                    'group_id': results_item_1[0],
                    'instance_id': results_item_2[0],
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': results_item_1[1]},
                })

    phantom.act(action="remove instance", parameters=parameters, assets=['aws_ec2'], callback=describe_instance_after, name="remove_existing_SGs", parent_action=action)

    return

"""
Gather EC2 instance metadata after changing the security groups to verify the change.
"""
def describe_instance_after(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('describe_instance_after() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'describe_instance_after' call
    results_data_1 = phantom.collect2(container=container, datapath=['describe_instance_before:action_result.parameter.instance_ids', 'describe_instance_before:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'describe_instance_after' call
    for results_item_1 in results_data_1:
        parameters.append({
            'limit': "",
            'dry_run': "",
            'filters': "",
            'instance_ids': results_item_1[0],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': results_item_1[1]},
        })

    phantom.act(action="describe instance", parameters=parameters, assets=['aws_ec2'], callback=describe_instance_after_callback, name="describe_instance_after", parent_action=action)

    return

def describe_instance_after_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('describe_instance_after_callback() called')
    
    format_note(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    list_connections_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    format_before(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Combine the before and after messages into a single comment.
"""
def format_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_comment() called')
    
    template = """Before this playbook run the instance {0} had the following security groups:

{1}

and after this playbook run the instance has the following security groups:

{2}"""

    # parameter list for template variable replacement
    parameters = [
        "describe_instance_before:action_result.parameter.instance_ids",
        "format_before:formatted_data",
        "format_after:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_comment")

    add_note_1(container=container)

    return

"""
Format a message describing the security groups before the change.
"""
def format_before(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_before() called')
    
    template = """%%
Security Group ID: {0}
Security Group Name: {1}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "describe_instance_before:action_result.data.*.Reservations.*.Instances.*.NetworkInterfaces.*.Groups.*.GroupId",
        "describe_instance_before:action_result.data.*.Reservations.*.Instances.*.NetworkInterfaces.*.Groups.*.GroupName",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_before")

    format_after(container=container)

    return

"""
Format a message describing the security groups after the change.
"""
def format_after(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_after() called')
    
    template = """%%
Security Group ID: {0}
Security Group Name: {1}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "describe_instance_after:action_result.data.*.Reservations.*.Instances.*.NetworkInterfaces.*.Groups.*.GroupId",
        "describe_instance_after:action_result.data.*.Reservations.*.Instances.*.NetworkInterfaces.*.Groups.*.GroupName",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_after")

    format_comment(container=container)

    return

"""
Post a comment describing the security group assignment before and after the change.
"""
def add_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_1() called')

    formatted_data_1 = phantom.get_format_data(name='format_comment')

    note_title = "Findings"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    CompleteTask(container=container)

    return

"""
Add a note to the Security Hub Finding to describe the change that was made.
"""
def AddNoteOnSecurityHub(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('AddNoteOnSecurityHub() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    source_data_identifier_value = container.get('source_data_identifier', None)

    # collect data for 'AddNoteOnSecurityHub' call
    formatted_data_1 = phantom.get_format_data(name='format_note')

    parameters = []
    
    # build parameters list for 'AddNoteOnSecurityHub' call
    parameters.append({
        'note': formatted_data_1,
        'overwrite': "",
        'findings_id': source_data_identifier_value,
    })

    phantom.act(action="add note", parameters=parameters, assets=['aws_security_hub'], name="AddNoteOnSecurityHub")

    return

"""
Format a note to add to the Finding in Security Hub.
"""
def format_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_note() called')
    
    template = """Phantom ran two playbooks investigating the EC2 instance {0} and isolating it from external networks by removing its previous security groups and assigning it to a quarantine security group. The event can be reviewed and further response can be taken using Investigation in Phantom: {1}"""

    # parameter list for template variable replacement
    parameters = [
        "describe_instance_before:action_result.parameter.instance_ids",
        "container:url",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_note")

    AddNoteOnSecurityHub(container=container)

    return

"""
List active TCP and UDP connections to show which traffic is still reaching the instance and to show that Phantom still has SSH access to the instance.
"""
def list_connections_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('list_connections_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'list_connections_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['describe_instance_after:action_result.data.*.Reservations.*.Instances.*.PublicDnsName', 'describe_instance_after:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'list_connections_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'local_addr': "",
                'local_port': "",
                'ip_hostname': results_item_1[0],
                'remote_addr': "",
                'remote_port': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="list connections", parameters=parameters, assets=['ssh'], callback=decision_4, name="list_connections_1", parent_action=action)

    return

def GetIsolationSecurityGroup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('GetIsolationSecurityGroup() called')
    
    input_parameter_0 = ""

    GetIsolationSecurityGroup__isolationGroup = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    success, message, results = phantom.get_list(list_name="globalconfig", values="isolation_sg", trace=False)
    phantom.debug('Printing success: {0}, message: {1}, results: {2}, '.format(success, message, results))
    
    isolation_sg = results['matches'][0]['value'][1]
    phantom.debug("Isolation Group: {}".format(isolation_sg))
    if not isolation_sg:
        GetIsolationSecurityGroup__isolationGroup = "badValue"
        phantom.debug('Isolation Group: BadValue - Check global config custom list')
        return
    
    GetIsolationSecurityGroup__isolationGroup = isolation_sg
    phantom.debug("Leaving - Isolation Group is: {}".format(GetIsolationSecurityGroup__isolationGroup))
    ########################################################
    ########################################################

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='GetIsolationSecurityGroup:isolationGroup', value=json.dumps(GetIsolationSecurityGroup__isolationGroup))
    decision_1(container=container)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["GetIsolationSecurityGroup:custom_function:isolationGroup", "==", "badValue"],
            ["GetIsolationSecurityGroup:custom_function:isolationGroup", "==", None],
        ],
        logical_operator='or')

    # call connected blocks if condition 1 matched
    if matched:
        FormatFailureNote(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    describe_instance_before(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def add_comment_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_2() called')

    phantom.comment(container=container, comment="Failed - No Isolation or Bad Isolation Security Group - Check globalconfig")

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')
    
    description_param = container.get('description', None)
    description_value = container.get('description', None)
    description_value = container.get('description', None)

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            [description_param, "==", "EC2 instance has an unprotected port which is being probed by a known malicious host."],
            ["Unprotected port on EC2 instance", "in", description_value],
            ["brute force attacks against", "in", description_value],
        ],
        logical_operator='or')

    # call connected blocks if condition 1 matched
    if matched:
        filter_ec2_resource(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

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
        add_comment_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    TaskInProgress(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def add_comment_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_3() called')

    phantom.comment(container=container, comment="Unable to get the current task id")

    return

def update_task_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_task_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    id_value = container.get('id', None)

    # collect data for 'update_task_1' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_set_event_owner_to_current_1:custom_function_result.data.currentOwner'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.task_id', 'cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='FormatFailureNote')

    parameters = []
    
    # build parameters list for 'update_task_1' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        for custom_function_results_item_2 in custom_function_results_data_2:
            parameters.append({
                'note': formatted_data_1,
                'user': custom_function_results_item_1[0],
                'status': "",
                'role_id': "",
                'task_id': custom_function_results_item_2[0],
                'task_name': "",
                'note_title': custom_function_results_item_2[1],
                'phase_name': "",
                'container_id': id_value,
            })

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], callback=add_comment_2, name="update_task_1")

    return

"""
Update failure note
"""
def FormatFailureNote(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('FormatFailureNote() called')
    
    template = """Get Security Group from globalconfig failed: 

Error: {0}"""

    # parameter list for template variable replacement
    parameters = [
        "GetIsolationSecurityGroup:custom_function:isolationGroup",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="FormatFailureNote")

    update_task_1(container=container)

    return

def CompleteTask(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('CompleteTask() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    id_value = container.get('id', None)

    # collect data for 'CompleteTask' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.task_id', 'cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name'], action_results=results)

    parameters = []
    
    # build parameters list for 'CompleteTask' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        parameters.append({
            'note': "Finished - If you need to rerun this playbook - revert the task status to not started and rerun",
            'user': "",
            'status': "complete",
            'role_id': "",
            'task_id': custom_function_results_item_1[0],
            'task_name': "",
            'note_title': custom_function_results_item_1[1],
            'phase_name': "",
            'container_id': id_value,
        })

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], name="CompleteTask")

    return

"""
Updates the task status to in-progress
"""
def TaskInProgress(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('TaskInProgress() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    id_value = container.get('id', None)

    # collect data for 'TaskInProgress' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_set_event_owner_to_current_1:custom_function_result.data.currentOwner'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.task_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'TaskInProgress' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        for custom_function_results_item_2 in custom_function_results_data_2:
            parameters.append({
                'note': "POV_EC2_Instance_Isolation - In Progress",
                'user': custom_function_results_item_1[0],
                'status': "in progress",
                'role_id': "",
                'task_id': custom_function_results_item_2[0],
                'task_name': "",
                'note_title': "Task Started",
                'phase_name': "",
                'container_id': id_value,
            })

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], callback=GetIsolationSecurityGroup, name="TaskInProgress")

    return

def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_4() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["list_connections_1:action_result.status", "==", "failed"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        add_comment_4(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def add_comment_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_4() called')

    phantom.comment(container=container, comment="List Connections After Moving Security Group Failed. SG Likely does not allow Phantom Access Now.")

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
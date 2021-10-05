"""
Investigate an AWS Security Hub finding related to an exposed EC2 instance which is being probed by potentially malicious traffic. Gather information about the EC2 configuration, the activity on the server, and any remote IP addresses that are directing traffic at the server. Notify and assign the appropriate people using a Jira ticket and a Slack message, then initiate a prompt to ask a responder whether or not the EC2 instance should be moved to an isolated EC2 Security Group using another playbook called "EC2 Instance Isolation".
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
    
    # call 'decision_severity_threshold' block
    decision_severity_threshold(container=container)

    return

"""
Separate the main Finding artifact from the other artifacts in the Finding.
"""
def filter_finding_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_finding_artifact() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.name", "==", "Finding Artifact"],
        ],
        name="filter_finding_artifact:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        parse_remote_ip_addrs(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Only proceed if there is an EC2 Resource contained in the SecurityHub Finding.
"""
def decision_ec2_resource(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_ec2_resource() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "AwsEc2Instance Resource Artifact"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_POV_set_event_owner_to_current_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    Parsing_Failure(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Collect the remote IP addresses described in the Finding.
"""
def parse_remote_ip_addrs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('parse_remote_ip_addrs() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_finding_artifact:condition_1:artifact:*.cef.ProductFields'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    parse_remote_ip_addrs__ip_addresses = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    parse_remote_ip_addrs__ip_addresses = []
    
    product_fields = filtered_artifacts_item_1_0[0]
    for key in list(product_fields.keys()):
        if 'remoteIpDetails/ipAddressV4' in key:
            parse_remote_ip_addrs__ip_addresses.append(product_fields[key])
    phantom.debug("remote ip addresses from finding:\n{}".format(parse_remote_ip_addrs__ip_addresses))

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='parse_remote_ip_addrs:ip_addresses', value=json.dumps(parse_remote_ip_addrs__ip_addresses))
    finding_format_ip(container=container)

    return

"""
Turn the IP addresses from the Finding into a list to allow usage in an action.
"""
def finding_format_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('finding_format_ip() called')
    
    template = """%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "parse_remote_ip_addrs:custom_function:ip_addresses",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="finding_format_ip")

    finding_geolocate_ip(container=container)
    finding_ip_reputation(container=container)

    return

"""
Determine the geolocation of the IP addresses seen in the Finding.
"""
def finding_geolocate_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('finding_geolocate_ip() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'finding_geolocate_ip' call
    formatted_data_1 = phantom.get_format_data(name='finding_format_ip__as_list')

    parameters = []
    
    # build parameters list for 'finding_geolocate_ip' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'ip': formatted_part_1,
        })

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], callback=join_CreateIPNote, name="finding_geolocate_ip")

    return

"""
Determine the reputation of the IP addresses seen in the Finding.
"""
def finding_ip_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('finding_ip_reputation() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'finding_ip_reputation' call
    formatted_data_1 = phantom.get_format_data(name='finding_format_ip__as_list')

    parameters = []
    
    # build parameters list for 'finding_ip_reputation' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'ip': formatted_part_1,
            'ph': "",
            'to': "",
            'from': "",
        })

    phantom.act(action="ip reputation", parameters=parameters, assets=['passivetotal'], callback=join_CreateIPNote, name="finding_ip_reputation")

    return

"""
Only proceed with this Finding if the SecurityHub normalized severity is above a certain threshold.
"""
def decision_severity_threshold(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_severity_threshold() called')
    
    description_param = container.get('description', None)
    description_param = container.get('description', None)
    description_value = container.get('description', None)

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            [description_param, "==", "EC2 instance has an unprotected port which is being probed by a known malicious host."],
            [description_param, "in", "Unprotected port on EC2 instance"],
            ["brute force attacks against", "in", description_value],
        ],
        logical_operator='or')

    # call connected blocks if condition 1 matched
    if matched:
        decision_ec2_resource(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def Parsing_Failure(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Parsing_Failure() called')

    phantom.pin(container=container, data="Failed", message="Parsing Resource Artifacts", pin_type="card", pin_style="red", name=None)

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
    phantom.custom_function(custom_function='local/POV_get_current_task', parameters=parameters, name='cf_local_POV_get_current_task_1', callback=decision_10)

    return

def decision_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_10() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_POV_get_current_task_1:custom_function_result.data.status", "==", "failed"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        add_comment_11(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    TaskInprogress(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def TaskInprogress(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('TaskInprogress() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'TaskInprogress' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_set_event_owner_to_current_1:custom_function_result.data.currentOwner'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.task_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'TaskInprogress' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        for custom_function_results_item_2 in custom_function_results_data_2:
            parameters.append({
                'note': "POV_EC2_Instance_Investigation In Progress",
                'user': custom_function_results_item_1[0],
                'status': "in progress",
                'role_id': "",
                'task_id': custom_function_results_item_2[0],
                'task_name': "",
                'note_title': "Task Started",
                'phase_name': "",
                'container_id': "",
            })

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], callback=filter_finding_artifact, name="TaskInprogress")

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

def add_comment_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_11() called')

    phantom.comment(container=container, comment="Unable to get the current task id")

    return

"""
Create Format block for Ip reputation & geolocate info
"""
def CreateIPNote(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('CreateIPNote() called')
    
    template = """#  {9} - Findings #
## Geolocate Action ##
### Probing IPs ###

| IP | Country | City |
|---|---|---|
%%
| {0} | {1} | {2} |
%%

## IP Reputation Action ##
### Probing IPs ###

| IP | Ever Compromised | SinkHole | Country | First Seen | Last Seen |
|---|---|---|---|---|---|
%%
| {3} | {4} | {5} | {6} | {7} | {8} |
%%"""

    # parameter list for template variable replacement
    parameters = [
        "finding_geolocate_ip:action_result.parameter.ip",
        "finding_geolocate_ip:action_result.data.*.country_name",
        "finding_geolocate_ip:action_result.data.*.city_name",
        "finding_ip_reputation:action_result.parameter.ip",
        "finding_ip_reputation:action_result.data.*.ever_compromised",
        "finding_ip_reputation:action_result.data.*.metadata.sinkhole",
        "finding_ip_reputation:action_result.data.*.metadata.country",
        "finding_ip_reputation:action_result.data.*.passive.firstSeen",
        "finding_ip_reputation:action_result.data.*.passive.lastSeen",
        "cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="CreateIPNote")

    AddIpNote(container=container)

    return

def join_CreateIPNote(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_CreateIPNote() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['finding_geolocate_ip', 'finding_ip_reputation']):
        
        # call connected block "CreateIPNote"
        CreateIPNote(container=container, handle=handle)
    
    return

"""
Add task Note
"""
def AddIpNote(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('AddIpNote() called')

    formatted_data_1 = phantom.get_format_data(name='CreateIPNote')

    note_title = "Findings"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    CompleteTask(container=container)

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
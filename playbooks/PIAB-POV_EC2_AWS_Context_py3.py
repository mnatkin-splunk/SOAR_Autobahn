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
Gather metadata about the EC2 instance in the Finding.
"""
def describe_ec2_instance(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('describe_ec2_instance() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'describe_ec2_instance' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_resource_artifact:condition_1:artifact:*.cef.InstanceId', 'filtered-data:filter_resource_artifact:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'describe_ec2_instance' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        parameters.append({
            'limit': "",
            'dry_run': "",
            'filters': "",
            'instance_ids': filtered_artifacts_item_1[0],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': filtered_artifacts_item_1[1]},
        })

    phantom.act(action="describe instance", parameters=parameters, assets=['aws_ec2'], callback=DescribeStatus, name="describe_ec2_instance")

    return

"""
Put together the relevant links, title, and description for the Finding to present to an analyst in both a ticket and a chat message.
"""
def format_description(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_description() called')
    
    template = """Phantom received a Security Hub Finding with the following details:

Finding title: {0}
Finding description: {1}
Phantom Mission Control link: {2}
AWS Security Hub Finding link: {3}"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "container:description",
        "container:url",
        "build_finding_url:custom_function:finding_url",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_description")

    return

"""
Separate the EC2 resource from the other artifacts in the Finding.
"""
def filter_resource_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_resource_artifact() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.name", "==", "AwsEc2Instance Resource Artifact"],
        ],
        name="filter_resource_artifact:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        describe_ec2_instance(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        GetAWSRegion(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

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
        build_finding_url(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

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
Use the Finding ID to construct a URL with a pre-populated SecurityHub search to view the Finding in the AWS Console.
"""
def build_finding_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('build_finding_url() called')
    
    GetAWSRegion__awsRegion = json.loads(phantom.get_run_data(key='GetAWSRegion:awsRegion'))
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_finding_artifact:condition_1:artifact:*.cef.Id'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    build_finding_url__finding_url = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # build a link to the Finding on Security Hub using a search as a URL parameter
    base = "https://console.aws.amazon.com/securityhub/home?region=" + GetAWSRegion__awsRegion + "#/findings?search=Id%3D%255Coperator%255C%253AEQUALS%255C%253A"
    build_finding_url__finding_url = base + filtered_artifacts_item_1_0[0].replace(':', '%253A').replace('/', '%252F')
    phantom.debug(build_finding_url__finding_url)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='build_finding_url:finding_url', value=json.dumps(build_finding_url__finding_url))
    format_description(container=container)

    return

"""
List the security groups that the EC2 instance belongs to. This should show the potentially vulnerable configuration described by the Finding.
"""
def list_security_groups_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('list_security_groups_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'list_security_groups_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['describe_ec2_instance:action_result.data.*.Reservations.*.Instances.*.SecurityGroups.*.GroupId', 'describe_ec2_instance:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'list_security_groups_1' call
    for results_item_1 in results_data_1:
        parameters.append({
            'dry_run': "",
            'filters': "",
            'group_ids': results_item_1[0],
            'next_token': "",
            'group_names': "",
            'max_results': "",
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': results_item_1[1]},
        })

    phantom.act(action="list security groups", parameters=parameters, assets=['aws_ec2'], callback=decision_11, name="list_security_groups_1")

    return

"""
Only proceed with this Finding if the SecurityHub normalized severity is above a certain threshold.
"""
def decision_severity_threshold(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_severity_threshold() called')
    
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
        decision_ec2_resource(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def Parsing_Failure(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Parsing_Failure() called')

    phantom.pin(container=container, data="Failed", message="Parsing Resource Artifacts", pin_type="card", pin_style="red", name=None)

    return

def DescribeStatus(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('DescribeStatus() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["describe_ec2_instance:action_result.status", "!=", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        DescribeFailedMessage(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    list_security_groups_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    PublicDNSName(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def GetAWSRegion(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('GetAWSRegion() called')
    
    input_parameter_0 = ""

    GetAWSRegion__awsRegion = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    success, message, results = phantom.get_list(list_name="globalconfig", values="aws_region", trace=False)
    phantom.debug('Printing success: {0}, message: {1}, results: {2}, '.format(success, message, results))
    
    aws_region = results['matches'][0]['value'][1]
    if not aws_region:
        GetAWSRegion__awsRegion = "badValue"
        phantom.debug('aws_region: BadValue - Check global config custom list')
        return
    
    GetAWSRegion__awsRegion = aws_region
    phantom.debug(GetAWSRegion__awsRegion)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='GetAWSRegion:awsRegion', value=json.dumps(GetAWSRegion__awsRegion))
    filter_finding_artifact(container=container)

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
    phantom.custom_function(custom_function='local/POV_get_current_task', parameters=parameters, name='cf_local_POV_get_current_task_1', callback=FunctionStatus)

    return

def FunctionStatus(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('FunctionStatus() called')

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
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name', 'cf_local_POV_get_current_task_1:custom_function_result.data.task_id'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_POV_set_event_owner_to_current_1:custom_function_result.data.currentOwner'], action_results=results)

    parameters = []
    
    # build parameters list for 'TaskInprogress' call
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
                'container_id': "",
            })

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], callback=filter_resource_artifact, name="TaskInprogress")

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

def CreateGeneralNote(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('CreateGeneralNote() called')
    
    template = """#  {0} - Findings #

## Describe Instances Action ##
** InstanceType : ** {1}

**Private DNS Name: ** {2}

** Public DNS Name: ** {3}

** Instance State: ** {4}

** Security Group: ** {5}

## List Security Group Action ##

** Group Name : **{10} 

| Protocol | Source | Port Range | Desc |
|---|---|---|---|
%%
| {8} | {6} | {7} | {9} |
%%"""

    # parameter list for template variable replacement
    parameters = [
        "cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name",
        "describe_ec2_instance:action_result.data.*.Reservations.*.Instances.*.InstanceType",
        "describe_ec2_instance:action_result.data.*.Reservations.*.Instances.*.NetworkInterfaces.*.PrivateDnsName",
        "describe_ec2_instance:action_result.data.*.Reservations.*.Instances.*.NetworkInterfaces.*.Association.PublicDnsName",
        "describe_ec2_instance:action_result.data.*.Reservations.*.Instances.*.State.Name",
        "describe_ec2_instance:action_result.data.*.Reservations.*.Instances.*.NetworkInterfaces.*.Groups.*.GroupName",
        "list_security_groups_1:action_result.data.*.SecurityGroups.*.IpPermissions.*.IpRanges.*.CidrIp",
        "list_security_groups_1:action_result.data.*.SecurityGroups.*.IpPermissions.*.FromPort",
        "list_security_groups_1:action_result.data.*.SecurityGroups.*.IpPermissions.*.IpProtocol",
        "list_security_groups_1:action_result.data.*.SecurityGroups.*.IpPermissions.*.IpRanges.*.Description",
        "list_security_groups_1:action_result.data.*.SecurityGroups.*.GroupName",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="CreateGeneralNote")

    add_note_12(container=container)

    return

def add_comment_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_11() called')

    phantom.comment(container=container, comment="Unable to get the current task id")

    return

def add_note_12(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_12() called')

    formatted_data_1 = phantom.get_format_data(name='CreateGeneralNote')

    note_title = "Findings"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    CompleteTask(container=container)

    return

"""
Create a formatted note
"""
def DescribeFailedMessage(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('DescribeFailedMessage() called')
    
    template = """Describe ec2 Instance action status: {0}

Failure Message :  {1}"""

    # parameter list for template variable replacement
    parameters = [
        "describe_ec2_instance:action_result.status",
        "describe_ec2_instance:action_result.message",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="DescribeFailedMessage")

    AddTaskNoteDescribeFailed(container=container)

    return

def AddTaskNoteDescribeFailed(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('AddTaskNoteDescribeFailed() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'AddTaskNoteDescribeFailed' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.task_id', 'cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='DescribeFailedMessage')

    parameters = []
    
    # build parameters list for 'AddTaskNoteDescribeFailed' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        parameters.append({
            'note': formatted_data_1,
            'user': "",
            'status': "",
            'role_id': "",
            'task_id': custom_function_results_item_1[0],
            'task_name': "",
            'note_title': custom_function_results_item_1[1],
            'phase_name': "",
            'container_id': "",
        })

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], name="AddTaskNoteDescribeFailed")

    return

def decision_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_11() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["list_security_groups_1:action_result.status", "==", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        CreateGeneralNote(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    ListGroupsFailedMessage(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def ListGroupsFailedMessage(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ListGroupsFailedMessage() called')
    
    template = """List Security Groups action status: {0}
Failure Message :  {1}"""

    # parameter list for template variable replacement
    parameters = [
        "list_security_groups_1:action_result.status",
        "list_security_groups_1:action_result.message",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="ListGroupsFailedMessage")

    AddTaskNoteListFailed(container=container)

    return

def AddTaskNoteListFailed(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('AddTaskNoteListFailed() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'AddTaskNoteListFailed' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.task_id', 'cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='ListGroupsFailedMessage')

    parameters = []
    
    # build parameters list for 'AddTaskNoteListFailed' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        parameters.append({
            'note': formatted_data_1,
            'user': "",
            'status': "",
            'role_id': "",
            'task_id': custom_function_results_item_1[0],
            'task_name': "",
            'note_title': custom_function_results_item_1[1],
            'phase_name': "",
            'container_id': "",
        })

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], name="AddTaskNoteListFailed")

    return

"""
Update the resource artefact with the public DNS Name (used in investigation playbook downstream)
"""
def updateResourceArtefact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('updateResourceArtefact() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    PublicDNSName__publicDNS = json.loads(phantom.get_run_data(key='PublicDNSName:publicDNS'))
    # collect data for 'updateResourceArtefact' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_resource_artifact:condition_1:artifact:*.id', 'filtered-data:filter_resource_artifact:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'updateResourceArtefact' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'data': PublicDNSName__publicDNS,
                'overwrite': "",
                'artifact_id': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="update artifact fields", parameters=parameters, assets=['phantomapp'], name="updateResourceArtefact")

    return

"""
Create a dict with the Public DNS Name to add to the resource artefact
"""
def PublicDNSName(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('PublicDNSName() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['describe_ec2_instance:action_result.data.*.Reservations.*.Instances.*.NetworkInterfaces.*.Association.PublicDnsName'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]

    PublicDNSName__publicDNS = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug('results data 1: {}'.format(results_item_1_0[0]))
    PublicDNSName__publicDNS = '{"cef": {"PublicDNSName": "' + results_item_1_0[0] + '"}}'
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='PublicDNSName:publicDNS', value=json.dumps(PublicDNSName__publicDNS))
    updateResourceArtefact(container=container)

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
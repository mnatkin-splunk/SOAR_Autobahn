"""
This playbook assigns the task to the account executing the playbook, sets the status to inprocessing and prompts the analyst to review the events presented to determine if we need to associate this event to another case or we need to create a case and associate other events to this case.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

import datetime

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'get_and_set_owner' block
    get_and_set_owner(container=container)

    return

def get_and_set_owner(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_and_set_owner() called')
    
    input_parameter_0 = ""

    get_and_set_owner__owner = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Gets playbook info to get current running user
    pb_info = phantom.get_playbook_info()
    #phantom.debug("Retreving owner name: {0}".format(pb_info))
    #phantom.debug(pb_info)
    
    # Sets owner
    phantom.set_owner(container=container, user=pb_info[0]["effective_user_id"])
    get_and_set_owner__owner = pb_info[0]["effective_user_id"]

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='get_and_set_owner:owner', value=json.dumps(get_and_set_owner__owner))
    user_url(container=container)

    return

"""
Using bogon list to review hostnames with internal IP addresses
"""
def check_user_host_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_user_host_info() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_username:artifact:*.cef.dest", "in", "custom_list:bogon_list"],
            ["get_username:artifact:*.cef.dest_ip", "in", "custom_list:bogon_list"],
            ["get_username:artifact:*.cef.destinationAddress", "in", "custom_list:bogon_list"],
            ["get_username:artifact:*.cef.destinationHostName", "not in", "custom_list:bogon_list"],
            ["get_username:artifact:*.cef.src", "in", "custom_list:bogon_list"],
            ["get_username:artifact:*.cef.src_ip", "in", "custom_list:bogon_list"],
            ["get_username:artifact:*.cef.sourceAddress", "in", "custom_list:bogon_list"],
            ["get_username:artifact:*.cef.sourceHostName", "not in", "custom_list:bogon_list"],
            ["get_username:artifact:*.cef.dhost", "not in", "custom_list:bogon_list"],
            ["get_username:artifact:*.cef.shost", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.dest_nt_host", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.src_nt_host", "not in", "custom_list:bogon_list"],
        ],
        logical_operator='or')

    # call connected blocks if condition 1 matched
    if matched:
        host_user_filter(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.destinationUserId", "!=", ""],
            ["artifact:*.cef.destinationUserName", "!=", ""],
            ["artifact:*.cef.duser", "!=", ""],
            ["artifact:*.cef.sourceUserId", "!=", ""],
            ["artifact:*.cef.sourceUserName", "!=", ""],
            ["artifact:*.cef.suser", "!=", ""],
        ],
        logical_operator='or')

    # call connected blocks if condition 2 matched
    if matched:
        join_user_info_filter(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 3
    Missing_information_comment(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def Missing_information_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Missing_information_comment() called')

    phantom.comment(container=container, comment="Missing necessary user or host information to process playbook")

    return

def host_user_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('host_user_filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.dest", "in", "custom_list:bogon_list"],
            ["artifact:*.cef.dest_ip", "in", "custom_list:bogon_list"],
            ["artifact:*.cef.destinationHostName", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.dhost", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.src", "in", "custom_list:bogon_list"],
            ["artifact:*.cef.src_ip", "in", "custom_list:bogon_list"],
            ["artifact:*.cef.sourceAddress", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.sourceHostName", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.shost", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.dest_nt_host", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.src_nt_host", "not in", "custom_list:bogon_list"],
        ],
        logical_operator='or',
        name="host_user_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        merge_hostnames(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def indicator_host_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('indicator_host_url() called')
    
    template = """%%
/indicator_by_value?tenant_id=0&indicator_value={0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "merge_hostnames:custom_function_result.data.*.item",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="indicator_host_url")

    get_host_indicators(container=container)

    return

def indicator_userid_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('indicator_userid_url() called')
    
    template = """%%
/indicator_by_value?tenant_id=0&indicator_value={0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "merge_usernames:custom_function_result.data.*.item",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="indicator_userid_url")

    get_userid_indicators(container=container)

    return

def get_host_indicators(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_host_indicators() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_host_indicators' call
    formatted_data_1 = phantom.get_format_data(name='indicator_host_url__as_list')

    parameters = []
    
    # build parameters list for 'get_host_indicators' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'headers': "",
            'location': formatted_part_1,
            'verify_certificate': False,
        })

    phantom.act(action="get data", parameters=parameters, assets=['phantom_rest_api'], callback=common_hosts_urls, name="get_host_indicators")

    return

def user_info_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('user_info_filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.destinationUserId", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.destinationUserName", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.duser", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.sourceUserId", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.sourceUserName", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.suser", "not in", "custom_list:bogon_list"],
        ],
        logical_operator='or',
        name="user_info_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        merge_usernames(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def join_user_info_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_user_info_filter() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_user_info_filter_called'):
        return

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['get_username', 'get_host_container_info']):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_user_info_filter_called', value='user_info_filter')
        
        # call connected block "user_info_filter"
        user_info_filter(container=container, handle=handle)
    
    return

def check_user_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_user_info() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.destinationUserId", "!=", ""],
            ["artifact:*.cef.destinationUserName", "!=", ""],
            ["artifact:*.cef.duser", "!=", ""],
            ["artifact:*.cef.sourceUserId", "!=", ""],
            ["artifact:*.cef.sourceUserName", "!=", ""],
            ["artifact:*.cef.suser", "!=", ""],
        ],
        logical_operator='or')

    # call connected blocks if condition 1 matched
    if matched:
        join_user_info_filter(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    join_container_host_info_format(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def get_userid_indicators(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_userid_indicators() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_userid_indicators' call
    formatted_data_1 = phantom.get_format_data(name='indicator_userid_url__as_list')

    parameters = []
    
    # build parameters list for 'get_userid_indicators' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'headers': "",
            'location': formatted_part_1,
            'verify_certificate': False,
        })

    phantom.act(action="get data", parameters=parameters, assets=['phantom_rest_api'], callback=common_userid_format, name="get_userid_indicators")

    return

"""
need to drop nones to make this work correctly.
"""
def common_userid_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('common_userid_format() called')
    
    template = """%%
/indicator_common_container?tenant_id=0&indicator_ids={0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "get_userid_indicators:action_result.data.*.response_body.id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="common_userid_format")

    get_common_userid(container=container)

    return

"""
Gets common containers for the indicators presented
"""
def get_common_userid(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_common_userid() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_common_userid' call
    formatted_data_1 = phantom.get_format_data(name='common_userid_format__as_list')

    parameters = []
    
    # build parameters list for 'get_common_userid' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'headers': "",
            'location': formatted_part_1,
            'verify_certificate': False,
        })

    phantom.act(action="get data", parameters=parameters, assets=['phantom_rest_api'], callback=container_userid_format, name="get_common_userid")

    return

def review_associated_events(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('review_associated_events() called')
    
    # Get container ids for the prompt
    host =  phantom.collect2(container=container, datapath=['get_host_container_info:action_result.data.*.response_body.id'], action_results=results)
    #phantom.debug(host)
    userid = phantom.collect2(container=container, datapath=['get_userid_container_info:action_result.data.*.response_body.id'], action_results=results)
    #phantom.debug(userid)
    
    # combines the container ids together to produce a single list
    containers = ['None']
    for item in host:
        containers.append(item[0])
    for item in userid:
        containers.append(item[0])
    # dedupe the list    
    containers = list(dict.fromkeys(containers))
    #phantom.debug(containers)

    # Gets the current username for the playbook to assign the prompt correctly
    user_info = phantom.collect2(container=container, datapath=['get_username:action_result.data.*.response_body.username'], action_results=results)
    #phantom.debug(user_info)
    user = user_info[0][0]
    
    message = """{0},

The following events could be related to your event.

The indicators you were reviewing are: 
User(s): {1}
Host(s): {2} 
Table below represents the associated events:
---

{3}"""

    # parameter list for template variable replacement
    parameters = [
        "get_username:action_result.data.*.response_body.first_name",
        "get_userid_indicators:action_result.data.*.response_body.value",
        "get_host_indicators:action_result.data.*.response_body.value",
        "create_note_data:custom_function:message",
    ]

    #responses:
    response_types = [
        {
            "prompt": "Do you want to create a case?",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No",
                ]
            },
        },
        {
            "prompt": "Select ID of Event e case (or is a case)",
            "options": {
                "type": "list",
                "choices": containers
            },
        },
        {
            "prompt": "Enter the Event IDs in comma separated value (e.g. 1,2,3 ) that you want to include in your case: (if you don't want to select a case just enter 0)",
            "options": {
                "type": "message",
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="review_associated_events", parameters=parameters, response_types=response_types, callback=validate_prompt)

    return

def user_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('user_url() called')
    
    template = """ph_user/{0}"""

    # parameter list for template variable replacement
    parameters = [
        "get_and_set_owner:custom_function:owner",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="user_url")

    get_username(container=container)

    return

def get_username(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_username() called')

    # collect data for 'get_username' call
    formatted_data_1 = phantom.get_format_data(name='user_url')

    parameters = []
    
    # build parameters list for 'get_username' call
    parameters.append({
        'headers': "",
        'location': formatted_data_1,
        'verify_certificate': False,
    })

    phantom.act(action="get data", parameters=parameters, assets=['phantom_rest_api'], callback=check_user_host_info, name="get_username")

    return

def container_userid_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('container_userid_format() called')
    
    template = """%%
container/{0}?_filter_status!=\"closed\"
%%"""

    # parameter list for template variable replacement
    parameters = [
        "get_common_userid:action_result.data.*.response_body.*.container_id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="container_userid_format")

    get_userid_container_info(container=container)

    return

def get_host_container_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_host_container_info() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_host_container_info' call
    formatted_data_1 = phantom.get_format_data(name='container_host_format__as_list')

    parameters = []
    
    # build parameters list for 'get_host_container_info' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'headers': "",
            'location': formatted_part_1,
            'verify_certificate': False,
        })

    phantom.act(action="get data", parameters=parameters, assets=['phantom_rest_api'], callback=check_user_info, name="get_host_container_info")

    return

"""
Using the key "baseurl" to do a dynamic replace in the prompt.
"""
def container_info_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('container_info_format() called')
    
    template = """| Type | Container Id | Container Name | Status | Owner | URL |
| --- | --- | --- | --- | --- | --- |
| ***User*** | data | below | ---- | ---- |---- |
%%
| {0} | {1} | {2} | {3} | {4} | base_url/mission/{1} |
%%
| ***Host*** | data | below | ---- | ---- | ---- |
{5}"""

    # parameter list for template variable replacement
    parameters = [
        "get_userid_container_info:action_result.data.*.response_body.container_type",
        "get_userid_container_info:action_result.data.*.response_body.id",
        "get_userid_container_info:action_result.data.*.response_body.name",
        "get_userid_container_info:action_result.data.*.response_body.status",
        "get_userid_container_info:action_result.data.*.response_body.owner_name",
        "container_host_info_format:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="container_info_format")

    create_note_data(container=container)

    return

def validate_prompt(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('validate_prompt() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["review_associated_events:action_result.status", "==", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        check_to_create_a_case(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    sla_expiration_comment(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def create_task_complete_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_task_complete_note() called')

    formatted_data_1 = phantom.get_format_data(name='general_note_format')

    note_title = "Associated Events"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def general_note_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('general_note_format() called')
    
    template = """### Analyst Review of associated events:

Analyst wanted to create a case: {1} with {2} and included the following IDs: {3}

---

Automation message to analyst:

{0}

---
created by {4} at {5}"""

    # parameter list for template variable replacement
    parameters = [
        "review_associated_events:action_result.parameter.message",
        "review_associated_events:action_result.summary.responses.0",
        "review_associated_events:action_result.summary.responses.1",
        "review_associated_events:action_result.summary.responses.2",
        "get_username:action_result.data.*.response_body.username",
        "create_note_data:custom_function:timestamp",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="general_note_format")

    create_task_complete_note(container=container)

    return

def join_general_note_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_general_note_format() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_general_note_format_called'):
        return

    # no callbacks to check, call connected block "general_note_format"
    phantom.save_run_data(key='join_general_note_format_called', value='general_note_format', auto=True)

    general_note_format(container=container, handle=handle)
    
    return

def check_to_create_a_case(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_to_create_a_case() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["review_associated_events:action_result.summary.responses.0", "==", "No"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        join_general_note_format(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    promote_or_merge(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def promote_or_merge(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('promote_or_merge() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['review_associated_events:action_result.summary.responses.1', 'review_associated_events:action_result.summary.responses.2'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['get_userid_container_info:action_result.data.*.response_body.id'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['get_host_container_info:action_result.data.*.response_body.id'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_1_1 = [item[1] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]
    results_item_3_0 = [item[0] for item in results_data_3]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Processing for the promote or merge
    # Prompt responses 
    responses = results_data_1[0]
    phantom.debug("Received notification to creates a case with {} and then merge IDs: {}".format(responses[0],responses[1]))
    merge_containers = responses[1].split(',')
    phantom.debug("Container IDs splited and to be merged: {}".format(merge_containers))
    
    message ="doing nothing"
    
    # Containers considered
    containers = results_item_2_0
    phantom.debug(containers)
    for item in results_item_3_0:
        containers.append(item)
    phantom.debug(containers)
    containers = list(dict.fromkeys(containers))
    phantom.debug("Full list of containers to use: {} and the current container is: {}".format(containers, container))

    if container == responses[0]:
        phantom.debug("Promoting this container: {}".format(container))
        success, message = phantom.promote()
    else:
        for item in containers:
            if item == responses[0]:
                phantom.debug("Promoting this container: {}".format(item))
                success, message = phantom.promote(container=item, template="NIST 800-61r2 Response Plan")
                phantom.debug("The following container was converted to case: ID: {}, message: {}".format(container,message))
    
    # Merge events into the the container promoted
    for container_id in merge_containers:
        success, message = phantom.merge(case=responses[0], container_id=container_id)
        phantom.debug('phantom.merge results: success {}, message: {}'.format(success, message))
        
        success, message = phantom.set_status(container=container_id, status='closed')
        phantom.debug(
            'phantom.set_status results: success: {}, message: {}'.format(success, message)
        )

    ################################################################################
    ## Custom Code End
    ################################################################################
    join_general_note_format(container=container)

    return

def sla_expiration_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('sla_expiration_comment() called')

    phantom.comment(container=container, comment="If SLA expired, just rerun the playbook. If failed notify an adminsitrator.")

    return

def common_hosts_urls(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('common_hosts_urls() called')
    
    template = """%%
/indicator_common_container?tenant_id=0&indicator_ids={0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "get_host_indicators:action_result.data.*.response_body.id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="common_hosts_urls")

    get_common_hosts(container=container)

    return

"""
Gets common containers for the indicators presented
"""
def get_common_hosts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_common_hosts() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_common_hosts' call
    formatted_data_1 = phantom.get_format_data(name='common_hosts_urls__as_list')

    parameters = []
    
    # build parameters list for 'get_common_hosts' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'headers': "",
            'location': formatted_part_1,
            'verify_certificate': False,
        })

    phantom.act(action="get data", parameters=parameters, assets=['phantom_rest_api'], callback=container_host_format, name="get_common_hosts")

    return

def container_host_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('container_host_format() called')
    
    template = """%%
container/{0}?_filter_status!=\"closed\"
%%"""

    # parameter list for template variable replacement
    parameters = [
        "get_common_hosts:action_result.data.*.response_body.*.container_id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="container_host_format")

    get_host_container_info(container=container)

    return

def get_userid_container_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_userid_container_info() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_userid_container_info' call
    formatted_data_1 = phantom.get_format_data(name='container_userid_format__as_list')

    parameters = []
    
    # build parameters list for 'get_userid_container_info' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'headers': "",
            'location': formatted_part_1,
            'verify_certificate': False,
        })

    phantom.act(action="get data", parameters=parameters, assets=['phantom_rest_api'], callback=join_container_host_info_format, name="get_userid_container_info")

    return

def container_host_info_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('container_host_info_format() called')
    
    template = """%%
| {0} | {1} | {2} | {3} | {4} | base_url/mission/{1} |
%%"""

    # parameter list for template variable replacement
    parameters = [
        "get_host_container_info:action_result.data.*.response_body.container_type",
        "get_host_container_info:action_result.data.*.response_body.id",
        "get_host_container_info:action_result.data.*.response_body.name",
        "get_host_container_info:action_result.data.*.response_body.status",
        "get_host_container_info:action_result.data.*.response_body.owner_name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="container_host_info_format")

    container_info_format(container=container)

    return

def join_container_host_info_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_container_host_info_format() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_container_host_info_format_called'):
        return

    # no callbacks to check, call connected block "container_host_info_format"
    phantom.save_run_data(key='join_container_host_info_format_called', value='container_host_info_format', auto=True)

    container_host_info_format(container=container, handle=handle)
    
    return

def create_note_data(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_note_data() called')
    
    formatted_data_1 = phantom.get_format_data(name='container_info_format')

    create_note_data__timestamp = None
    create_note_data__message = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Get base url and format link customer
    url = phantom.get_base_url()
    phantom.debug("Base url is: {}".format(url))
    create_note_data__message = formatted_data_1.replace("base_url", url)
    
    # Get the date timestamp
    create_note_data__timestamp = datetime.datetime.now().strftime("%c")
    phantom.debug("The current timestamp is: {}".format(create_note_data__timestamp))

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='create_note_data:timestamp', value=json.dumps(create_note_data__timestamp))
    phantom.save_run_data(key='create_note_data:message', value=json.dumps(create_note_data__message))
    review_associated_events(container=container)

    return

def merge_hostnames(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('merge_hostnames() called')
    
    filtered_artifacts_data_0 = phantom.collect2(container=container, datapath=['filtered-data:host_user_filter:condition_1:artifact:*.cef.destinationAddress', 'filtered-data:host_user_filter:condition_1:artifact:*.cef.dest_ip', 'filtered-data:host_user_filter:condition_1:artifact:*.cef.destinationHostName', 'filtered-data:host_user_filter:condition_1:artifact:*.cef.dhost', 'filtered-data:host_user_filter:condition_1:artifact:*.cef.sourceAddress', 'filtered-data:host_user_filter:condition_1:artifact:*.cef.src_ip', 'filtered-data:host_user_filter:condition_1:artifact:*.cef.sourceHostName', 'filtered-data:host_user_filter:condition_1:artifact:*.cef.shost'])

    parameters = []

    filtered_artifacts_data_0_0 = [item[0] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_1 = [item[1] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_2 = [item[2] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_3 = [item[3] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_4 = [item[4] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_5 = [item[5] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_6 = [item[6] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_7 = [item[7] for item in filtered_artifacts_data_0]

    parameters.append({
        'input_1': filtered_artifacts_data_0_0,
        'input_2': filtered_artifacts_data_0_1,
        'input_3': filtered_artifacts_data_0_2,
        'input_4': filtered_artifacts_data_0_3,
        'input_5': filtered_artifacts_data_0_4,
        'input_6': filtered_artifacts_data_0_5,
        'input_7': filtered_artifacts_data_0_6,
        'input_8': filtered_artifacts_data_0_7,
        'input_9': None,
        'input_10': None,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "enrichment/list_merge_dedup", returns the custom_function_run_id
    phantom.custom_function(custom_function='enrichment/list_merge_dedup', parameters=parameters, name='merge_hostnames', callback=indicator_host_url)

    return

def merge_usernames(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('merge_usernames() called')
    
    filtered_artifacts_data_0 = phantom.collect2(container=container, datapath=['filtered-data:user_info_filter:condition_1:artifact:*.cef.destinationUserId', 'filtered-data:user_info_filter:condition_1:artifact:*.cef.destinationUserName', 'filtered-data:user_info_filter:condition_1:artifact:*.cef.duser', 'filtered-data:user_info_filter:condition_1:artifact:*.cef.sourceUserId', 'filtered-data:user_info_filter:condition_1:artifact:*.cef.sourceUserName', 'filtered-data:user_info_filter:condition_1:artifact:*.cef.suser'])

    parameters = []

    filtered_artifacts_data_0_0 = [item[0] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_1 = [item[1] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_2 = [item[2] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_3 = [item[3] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_4 = [item[4] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_5 = [item[5] for item in filtered_artifacts_data_0]

    parameters.append({
        'input_1': filtered_artifacts_data_0_0,
        'input_2': filtered_artifacts_data_0_1,
        'input_3': filtered_artifacts_data_0_2,
        'input_4': filtered_artifacts_data_0_3,
        'input_5': filtered_artifacts_data_0_4,
        'input_6': filtered_artifacts_data_0_5,
        'input_7': None,
        'input_8': None,
        'input_9': None,
        'input_10': None,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "enrichment/list_merge_dedup", returns the custom_function_run_id
    phantom.custom_function(custom_function='enrichment/list_merge_dedup', parameters=parameters, name='merge_usernames', callback=indicator_userid_url)

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
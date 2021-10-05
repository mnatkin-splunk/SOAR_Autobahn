"""
This playbook processes usernames and hostnames not in bogon_list and creates a task note for every indicator for review by the analyst
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

import re

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'check_user_or_host' block
    check_user_or_host(container=container)

    return

def check_user_or_host(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_user_or_host() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationUserName", "!=", ""],
            ["artifact:*.cef.destinationUserId", "!=", ""],
            ["artifact:*.cef.sourceUserId", "!=", ""],
            ["artifact:*.cef.sourceUserName", "!=", ""],
            ["artifact:*.cef.duser", "!=", ""],
            ["artifact:*.cef.suser", "!=", ""],
            ["artifact:*.cef.user", "!=", ""],
            ["artifact:*.cef.destinationHostName", "!=", ""],
            ["artifact:*.cef.sourceHostName", "!=", ""],
            ["artifact:*.cef.dhost", "!=", ""],
            ["artifact:*.cef.shost", "!=", ""],
            ["artifact:*.cef.hostname", "!=", ""],
        ],
        logical_operator='or')

    # call connected blocks if condition 1 matched
    if matched:
        user_system_filter(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    missing_data_comment(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def user_system_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('user_system_filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationUserId", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.destinationUserName", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.duser", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.sourceUserId", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.sourceUserName", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.suser", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.user", "==", "custom_list:bogon_list"],
        ],
        logical_operator='or',
        name="user_system_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        merge_usernames(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationHostName", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.dhost", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.shost", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.sourceHostName", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.dest", "not in", "custom_list:bogon_list"],
            ["artifact:*.cef.dest_nt_host", "not in", "custom_list:bogon_list"],
        ],
        logical_operator='or',
        name="user_system_filter:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        merge_hostnames(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def get_customer_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_customer_info() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_customer_info' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['merge_usernames:custom_function_result.data.*.item'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_customer_info' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'fields': "",
                'username': custom_function_results_item_1[0],
                'attribute': "",
            })

    phantom.act(action="get user attributes", parameters=parameters, assets=['domainctrl1'], callback=get_manager, name="get_customer_info")

    return

"""
Input 0 = Workbook Task to update with notes
"""
def generate_task_notes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('generate_task_notes() called')
    
    input_parameter_0 = "Validate customer and endpoint Information"
    results_data_1 = phantom.collect2(container=container, datapath=['get_customer_info:action_result.parameter.username', 'get_customer_info:action_result.data.*.manager'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='customer_info_format__as_list')
    formatted_data_2 = phantom.get_format_data(name='manager_format__as_list')
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_1_1 = [item[1] for item in results_data_1]

    generate_task_notes__note_params = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    """ Maps inputs to processing values and adds debugs for task default template """
    note_params = []
    
    """ Modify for # of notes created per # of indicators example below of 5 means 
        more than 5 indicators found will produce 1 note vs 5 notes. For a maximum of 20 indicators (ip, domain, url, filehash) """
    note_limit = 5
    
    # Debug input data
    phantom.debug("Customer data")
    #phantom.debug(formatted_data_1)
    customer_data = formatted_data_1
    
    # Debug input data
    phantom.debug("Mnaager data")
    #phantom.debug(formatted_data_2)
    manager_data = formatted_data_2

    phantom.debug("Indicator Processed")
    #phantom.debug(results_data_1)
    indicators = results_data_1
    
    no_manager = "### No Manager found"
    # Organize IOCs by value with correct data for note insertion
    for indicator in indicators:
        if not indicator[1]:
            indicator[1] = "empty"
        for customer in customer_data:
            if indicator[0] in customer:
                customer = re.sub('(manager_id:.*)', '', customer)
                indicator.append(customer)
        for manager in manager_data:
            if indicator[1] == "empty":
                indicator.append(no_manager)
            elif indicator[1] in manager:
                manager = re.sub('(manager_id:.*)', '', manager)
                indicator.append(manager)
    
    phantom.debug("Reorganzied note data to indicator.")
    #phantom.debug(indicators)
    
    # Get workbook phase id
    phantom.debug('Getting current phase')

    success, message, phase_id, phase_name = phantom.get_phase()

    phantom.debug(
        'phantom.get_phase results: success: {}, message: {}, phase_id: {}, phase_name: {}'.format(success, message, phase_id, phase_name)
    )
    
    # Task data for adding task notes
    task_data = {}
    
    # Get the tasks for start of the workbook
    for task in phantom.get_tasks(container=container):
        ## gets the current phase and 1st task
        if phase_id == task['data']['phase'] and task['data']['name'] == input_parameter_0:
            task_data.update(task['data'])
            phantom.debug('phantom.get_tasks found the task: task_id: {}, task_name: {}'.format(task_data['id'],task_data['name']))

    """ Create multiple single indicator note or multiple notes (cusotmer defined)
        Change the indicators length to greater than 5 artifacts if you want more notes created
        The maximum number of notes you want created is related to the number of indicators present."""
    
    title = "Customer Information Report"
    if len(indicators) <= note_limit:
        # Create loop for creating multiple notes under the same task
        phantom.debug("Found {} indicators.".format(len(indicators)))
        phantom.debug("Creating Multiple indicator notes.")
        for indicator in indicators: 
            # Define Note content build here
            note_content = "{}{}".format(indicator[2],indicator[3])
            #phantom.debug("Multi-Note content: \n {}".format(note_content))
        
            # Build note parameters
            note_params.append({
                "note_type": "task",
                "task_id": task_data['id'],
                "container_id": container['id'],
                "title": title + " for {}".format(indicator[0]),
                "content": note_content,
                "note_format": "markdown",
                "phase_id": phase_id
            })
    else:
        phantom.debug("Found {} indicators.".format(len(indicators)))
        phantom.debug("Creating Single indicator notes.")
        note_content = ""
        for indicator in indicators: 
            # Define Note content build here
            note_content += "## Customer Information for {}\n {}{}".format(indicator[0],indicator[2],indicator[3])
            #phantom.debug("Single Note content: \n {}".format(note_content))

        # Build note parameters
        note_params.append({
            "note_type": "task",
            "task_id": task_data['id'],
            "container_id": container['id'],
            "title": title,
            "content": note_content,
            "note_format": "markdown",
            "phase_id": phase_id
        })    
        
    # Save parameters for REST calls to update
    #phantom.debug("Debug Parameters:")
    generate_task_notes__note_params = note_params

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='generate_task_notes:note_params', value=json.dumps(generate_task_notes__note_params))
    create_customer_notes(container=container)

    return

"""
Create for loop for parameters.append() and json.dumps() the note_params.

custom code needed:
    # build parameters list for 'create_task_notes' call
    for note_params in generate_task_notes__note_params:
        parameters.append({
            'body': json.dumps(note_params),
            'headers': "",
            'location': "/note/",
            'verify_certificate': False,
        })
"""
def create_customer_notes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_customer_notes() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    generate_task_notes__note_params = json.loads(phantom.get_run_data(key='generate_task_notes:note_params'))
    # collect data for 'create_customer_notes' call

    parameters = []
    
    # build parameters list for 'create_customer_notes' call
    for note_params in generate_task_notes__note_params:
        parameters.append({
            'location': "/note/",
            'body': json.dumps(note_params),
            'headers': "",
            'verify_certificate': False,
        })

    phantom.act(action="post data", parameters=parameters, assets=['phantom_rest_api'], name="create_customer_notes")

    return

def customer_info_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('customer_info_format() called')
    
    template = """%%
### User Infromation for {0}: *{1}, {2}*
### {3}

Minimum information should be:

| Attribute | Value |
| ---- | ---- |
| Company | {4} |
| Business Unit | {5} |
| Phone # | {6} |
| Country Code | {7} |
| Primary Group ID | {8} |
| Object SID Type | {9} |
| Object Category | {10} |
| User Account Control | {11} |
| Distinguished Name | {12} |
Member of:  {13}  
manager_id: 
%%"""

    # parameter list for template variable replacement
    parameters = [
        "get_customer_info:action_result.parameter.username",
        "get_customer_info:action_result.data.*.displayname",
        "get_customer_info:action_result.data.*.mail",
        "get_customer_info:action_result.message",
        "get_customer_info:action_result.data.*.company",
        "get_customer_info:action_result.data.*.department",
        "get_customer_info:action_result.data.*.telephoneNumber",
        "get_customer_info:action_result.data.*.countrycode",
        "get_customer_info:action_result.data.*.primarygroupid",
        "get_customer_info:action_result.data.*.company",
        "get_customer_info:action_result.data.*.objectcategory",
        "get_customer_info:action_result.data.*.useraccountcontrol",
        "get_customer_info:action_result.data.*.distinguishedname",
        "get_customer_info:action_result.data.*.memberof",
        "get_customer_info:action_result.data.*.manager",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="customer_info_format")

    generate_task_notes(container=container)

    return

def get_system_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_system_info() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_system_info' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['merge_hostnames:custom_function_result.data.*.item'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_system_info' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'fields': "",
                'hostname': custom_function_results_item_1[0],
            })

    phantom.act(action="get system attributes", parameters=parameters, assets=['domainctrl1'], callback=system_info_format, name="get_system_info")

    return

def system_info_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('system_info_format() called')
    
    template = """%%
### System Information for {0}: *{1}*
{2}

| Attribute | Value |
| ---- | ---- |
| DNS Host Name | {3} |
| Country Code | {4} |
| Object Category | {5} |
| Primary Group ID | {6} |
| Distinguished Name | {7} |

----

%%"""

    # parameter list for template variable replacement
    parameters = [
        "get_system_info:action_result.parameter.hostname",
        "get_system_info:action_result.data.*.operatingsystem",
        "get_system_info:action_result.message",
        "get_system_info:action_result.data.*.dnshostname",
        "get_system_info:action_result.data.*.countrycode",
        "get_system_info:action_result.data.*.objectcategory",
        "get_system_info:action_result.data.*.primarygroupid",
        "get_system_info:action_result.data.*.distinguishedname",
        "get_system_info:action_result.data.*.serviceprincipalname",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="system_info_format")

    generate_system_note(container=container)

    return

def missing_data_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('missing_data_comment() called')

    phantom.comment(container=container, comment="Missing data to execute playbook.  Check logic and playbook parameters")

    return

def get_manager(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_manager() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_manager' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_customer_info:action_result.data.*.manager', 'get_customer_info:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_manager' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'fields': "",
                'username': results_item_1[0],
                'attribute': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="get user attributes", parameters=parameters, assets=['domainctrl1'], callback=manager_format, name="get_manager", parent_action=action)

    return

"""
Input 0 = Workbook Task to update with notes
"""
def generate_system_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('generate_system_note() called')
    
    input_parameter_0 = "Validate customer and endpoint Information"
    results_data_1 = phantom.collect2(container=container, datapath=['get_system_info:action_result.parameter.hostname'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='system_info_format__as_list')
    results_item_1_0 = [item[0] for item in results_data_1]

    generate_system_note__note_params = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    #""" Maps inputs to processing values and adds debugs for task default template """
    note_params = []
    
    """ Modify for # of notes created per # of indicators example below of 5 means 
        more than 5 indicators found will produce 1 note vs 5 notes. For a maximum of 20 indicators (ip, domain, url, filehash) """
    note_limit = 5
    
    # Debug input data
    phantom.debug("System data:")
    #phantom.debug(formatted_data_1)
    system_data = formatted_data_1
    
    phantom.debug("Indicator Processed")
    #phantom.debug(custom_function_results_data_1)
    indicators = results_item_1_0
    
    for indicator in indicators:
        for system in system_data:
            if indicator[0] in system:
                indicator.append(system)
    
    phantom.debug("Reorganzied note data to indicator.")
    #phantom.debug(indicators)

    # Get workbook phase id
    phantom.debug('Getting current phase')

    success, message, phase_id, phase_name = phantom.get_phase()

    phantom.debug(
        'phantom.get_phase results: success: {}, message: {}, phase_id: {}, phase_name: {}'.format(success, message, phase_id, phase_name)
    )
    
    # Task data for adding task notes
    task_data = {}
    
    # Get the tasks for start of the workbook
    for task in phantom.get_tasks(container=container):
        ## gets the current phase and 1st task
        if phase_id == task['data']['phase'] and task['data']['name'] == input_parameter_0:
            task_data.update(task['data'])
            phantom.debug('phantom.get_tasks found the task: task_id: {}, task_name: {}'.format(task_data['id'],task_data['name']))

    """ Create multiple single indicator note or multiple notes (cusotmer defined)
        Change the indicators length to greater than 5 artifacts if you want more notes created
        The maximum number of notes you want created is related to the number of indicators present."""
    
    title = "System Information Report"
    if len(indicators) <= note_limit:
        # Create loop for creating multiple notes under the same task
        phantom.debug("Found {} indicators.".format(len(indicators)))
        phantom.debug("Creating Multiple indicator notes.")
        for indicator in indicators:
            # Define Note content build here
            note_content = "{}\n".format(indicator[1])
            #phantom.debug("Multi-Note content: \n {}".format(note_content))
        
            # Build note parameters
            note_params.append({
                "note_type": "task",
                "task_id": task_data['id'],
                "container_id": container['id'],
                "title": title + " for {}".format(indicator[0]),
                "content": note_content,
                "note_format": "markdown",
                "phase_id": phase_id
            })
    else:
        # Creates one note for all system information presented
        phantom.debug("Found {} indicators.".format(len(indicators)))
        phantom.debug("Creating Single indicator notes.")
        note_content = ""
        for indicator in indicators: 
            # Define Note content build here
            note_content += "## System Information for {}\n {}\n ".format(indicator[0],indicator[1])
            #phantom.debug("Single Note content: \n {}".format(note_content))

        # Build note parameters
        note_params.append({
            "note_type": "task",
            "task_id": task_data['id'],
            "container_id": container['id'],
            "title": title,
            "content": note_content,
            "note_format": "markdown",
            "phase_id": phase_id
        })    
        
    # Save parameters for REST calls to update
    phantom.debug("Created Note Parameters:")
    generate_system_note__note_params = note_params

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='generate_system_note:note_params', value=json.dumps(generate_system_note__note_params))
    create_system_note(container=container)

    return

"""
Create for loop for parameters.append() and json.dumps() the note_params.

custom code needed:
    # build parameters list for 'create_task_notes' call
    for note_params in generate_task_notes__note_params:
        parameters.append({
            'body': json.dumps(note_params),
            'headers': "",
            'location': "/note/",
            'verify_certificate': False,
        })
"""
def create_system_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_system_note() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    generate_system_note__note_params = json.loads(phantom.get_run_data(key='generate_system_note:note_params'))
    # collect data for 'create_system_note' call

    parameters = []
    
    # build parameters list for 'create_system_note' call
    for note_params in generate_system_note__note_params:
        parameters.append({
            'location': "/note/",
            'body': json.dumps(note_params),
            'headers': "",
            'verify_certificate': False,
        })

    phantom.act(action="post data", parameters=parameters, assets=['phantom_rest_api'], name="create_system_note")

    return

def manager_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('manager_format() called')
    
    template = """%%
| Attribute | Value |
| ---- | ---- |
| Manager | {0} |
| Manager Email | {1} |
| Manager Phone | {2} |
manager_id: {3}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "get_manager:action_result.data.*.displayname",
        "get_manager:action_result.data.*.mail",
        "get_manager:action_result.data.*.telephoneNumber",
        "get_manager:action_result.parameter.username",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="manager_format")

    customer_info_format(container=container)

    return

def set_status_to_new(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_to_new() called')

    phantom.set_status(container=container, status="New")

    return

def join_set_status_to_new(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_set_status_to_new() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_set_status_to_new_called'):
        return

    # no callbacks to check, call connected block "set_status_to_new"
    phantom.save_run_data(key='join_set_status_to_new_called', value='set_status_to_new', auto=True)

    set_status_to_new(container=container, handle=handle)
    
    return

def merge_usernames(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('merge_usernames() called')
    
    filtered_artifacts_data_0 = phantom.collect2(container=container, datapath=['filtered-data:user_system_filter:condition_1:artifact:*.cef.destinationUserId', 'filtered-data:user_system_filter:condition_1:artifact:*.cef.destinationUserName', 'filtered-data:user_system_filter:condition_1:artifact:*.cef.duser', 'filtered-data:user_system_filter:condition_1:artifact:*.cef.sourceUserId', 'filtered-data:user_system_filter:condition_1:artifact:*.cef.sourceUserName', 'filtered-data:user_system_filter:condition_1:artifact:*.cef.suser'])

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
    phantom.custom_function(custom_function='enrichment/list_merge_dedup', parameters=parameters, name='merge_usernames', callback=get_customer_info)

    return

def merge_hostnames(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('merge_hostnames() called')
    
    filtered_artifacts_data_0 = phantom.collect2(container=container, datapath=['filtered-data:user_system_filter:condition_2:artifact:*.cef.destinationAddress', 'filtered-data:user_system_filter:condition_2:artifact:*.cef.dest_ip', 'filtered-data:user_system_filter:condition_2:artifact:*.cef.destinationHostName', 'filtered-data:user_system_filter:condition_2:artifact:*.cef.dhost', 'filtered-data:user_system_filter:condition_2:artifact:*.cef.sourceAddress', 'filtered-data:user_system_filter:condition_2:artifact:*.cef.src_ip', 'filtered-data:user_system_filter:condition_2:artifact:*.cef.sourceHostName', 'filtered-data:user_system_filter:condition_2:artifact:*.cef.shost'])

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
    phantom.custom_function(custom_function='enrichment/list_merge_dedup', parameters=parameters, name='merge_hostnames', callback=get_system_info)

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
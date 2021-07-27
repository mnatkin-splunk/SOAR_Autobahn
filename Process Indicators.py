"""
This playbook assigns the event, task and prompt to the analyst that runs the playbook and upon a proper response assigns the appropriate tag to the container for reporting and notable creation.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

import re
import datetime

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'workbook_task_url' block
    workbook_task_url(container=container)

    return

def in_process_task_body(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('in_process_task_body() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['get_analysis_task:action_result.data.*.response_body.data'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]

    in_process_task_body__task_body = None
    in_process_task_body__task_id = None
    in_process_task_body__owner = None
    in_process_task_body__note_data = None
    in_process_task_body__task_name = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
        
    # Gets playbook info to get current running user
    in_process_task_body__owner = 0
    pb_info = phantom.get_playbook_info()
    phantom.debug("Retreving owner name: {0}".format(pb_info[0]["effective_user_id"]))
    in_process_task_body__owner = pb_info[0]["effective_user_id"]
    
    # Get tasks and update task body
    task_data = []
    in_process_task_body__task_body = []
    # Add task stat to process
    task_data = results_data_1[0][0][0]
    #phantom.debug(task_data)
    
    # Assign new attributes to task body
    if task_data:
        # Set owner
        in_process_task_body__task_body = {
            "owner": in_process_task_body__owner,
            "is_note_required": False,
            "status" : 2
        }         
        in_process_task_body__task_id = task_data["id"]
        in_process_task_body__note_data = task_data["notes"]
        in_process_task_body__task_name = task_data["name"]
    else:
        phantom.debug("There is an error as no task was presented to the block. We should not get here from the blocking decision.")
               
    phantom.debug("We are updating Task Id: {} named {}".format(in_process_task_body__task_id,in_process_task_body__task_name))
    #phantom.debug(in_process_task_body__task_body)
    #phantom.debug(in_process_task_body__note_data)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='in_process_task_body:task_body', value=json.dumps(in_process_task_body__task_body))
    phantom.save_run_data(key='in_process_task_body:task_id', value=json.dumps(in_process_task_body__task_id))
    phantom.save_run_data(key='in_process_task_body:owner', value=json.dumps(in_process_task_body__owner))
    phantom.save_run_data(key='in_process_task_body:note_data', value=json.dumps(in_process_task_body__note_data))
    phantom.save_run_data(key='in_process_task_body:task_name', value=json.dumps(in_process_task_body__task_name))
    task_url_format(container=container)

    return

def validate_confidence_level(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('validate_confidence_level() called')
    
    # Set user and message variables for phantom.prompt call
    # Gets the current username for the playbook to assign the prompt correctly
    user_info = phantom.collect2(container=container, datapath=['get_current_user_settings:action_result.data.*.response_body.username', 'get_current_user_settings:action_result.data.*.response_body.first_name'], action_results=results)
    #phantom.debug(user_info)
    
    # Assigns the username for prompt assignment
    user = user_info[0][0]
    first_name = user_info[0][1]
    
    # Gets the note data to loop thru and set the title for 
    note_data = phantom.collect2(container=container, datapath=['get_analysis_task:action_result.data.*.response_body.data.*.notes'], action_results=results)[0][0]
    #phantom.debug(note_data)
    
    # Called out for using append() function for loop
    response_types = [{
            "prompt": "Analyst's Confidence Comments:",
            "options": {
                "type": "message",
            },
        },
    ]
    title = ""
    
    # Loops thru notes and parses out indicator and title for use in message and prompt
    for note in note_data:
        if not note['title'].startswith("Automated "):
            title += note["title"] + '\n\r'
            indicator = re.search('Indicator: (.*?)\|', note['title']).group(1).strip()
            phantom.debug("Processing prompt for indicator: {}".format(indicator))

            #responses:
            response_types.append({
                "prompt": indicator,
                "options": {
                    "type": "list",
                    "choices": [
                        "High",
                        "Medium",
                        "Low",
                    ]
                },
            }
            )

    message = """{}, 
Please take time to review the Note(s):\n\r {}
Determine the Indicator Threat Confidence for up to 20 indicators presented.

Please see the task description for any additional details on this task.""".format(first_name,title)

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=15, name="validate_confidence_level", response_types=response_types, callback=validate_threat_level)

    return

def evaluate_prompt(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('evaluate_prompt() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["validate_confidence_level:action_result.status", "==", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        update_note_and_task(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    failure_or_SLA_violation(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def task_url_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('task_url_format() called')
    
    template = """/workflow_task/{0}"""

    # parameter list for template variable replacement
    parameters = [
        "in_process_task_body:custom_function:task_id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="task_url_format")

    update_task_to_inprocess(container=container)

    return

"""
use get_task() & get_note()
"""
def update_note_and_task(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_note_and_task() called')
    
    in_process_task_body__task_body = json.loads(phantom.get_run_data(key='in_process_task_body:task_body'))
    results_data_1 = phantom.collect2(container=container, datapath=['get_analysis_task:action_result.data.*.response_body.data.*.notes'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['validate_confidence_level:action_result.summary.responses'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['validate_threat_level:action_result.summary.responses'], action_results=results)
    results_data_4 = phantom.collect2(container=container, datapath=['determine_threat_type:action_result.summary.responses'], action_results=results)
    results_data_5 = phantom.collect2(container=container, datapath=['get_current_user_settings:action_result.data.*.response_body.username'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]
    results_item_3_0 = [item[0] for item in results_data_3]
    results_item_4_0 = [item[0] for item in results_data_4]
    results_item_5_0 = [item[0] for item in results_data_5]

    update_note_and_task__note_body = None
    update_note_and_task__task_body = None
    update_note_and_task__note_id = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Update note body with Analyst comments 
    ## Debug notes and analyst responses
    notes_data = results_data_1[0][0]
    #phantom.debug(notes_data)
    
    confidence = results_data_2[0][0]
    #phantom.debug(confidence)
    
    threat = results_data_3[0][0]
    #phantom.debug(threat)
    
    threat_type = results_data_4[0][0]
    #phantom.debug(threat_type)
    
    username = results_data_5[0][0]
    #phantom.debug(username)
    
    # get current time in iso format
    timestamp = datetime.datetime.now().isoformat()
    
    # New reviewed title
    comments = """## Analyst's Comments:\n\r -Threat Type: {}\n\r -Threat Level Comment: {}\n\r -Threat Confidence: {}\n\r Updaated by: {} on {}\n\r---\n\r""".format(threat_type[0],threat[0],confidence[0],username,timestamp)
    index = 1

    # Updates Note from Analyst response
    update_note_and_task__note_body = []
    update_note_and_task__note_id = []
    for note in notes_data:
        if not note['title'].startswith("Automated "):
            reviewed = "| Type: {} | Threat: {} | Confidence: {} - Analyst Reviewed".format(threat_type[index],threat[index],confidence[index])
            phantom.debug("The reviewed title is: {}".format(reviewed))
            title = re.sub('(\| Threat:.*)', '', note['title'])

            update_note_and_task__note_body.append({
                'title': title + reviewed,
                'content': comments + note['content'],
            }
            )
            update_note_and_task__note_id.append(note['id'])
            index += 1
        
    # Assign new attributes to task body
    update_note_and_task__task_body = {}
    if in_process_task_body__task_body:
        # Changes status to completed
        update_note_and_task__task_body['status'] = 1
        update_note_and_task__task_body['is_note_required'] = False
        #phantom.debug(update_note_and_task__task_body)
            
    #phantom.debug(update_note_and_task__note_body)
    #phantom.debug(update_note_and_task__note_id)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='update_note_and_task:note_body', value=json.dumps(update_note_and_task__note_body))
    phantom.save_run_data(key='update_note_and_task:task_body', value=json.dumps(update_note_and_task__task_body))
    phantom.save_run_data(key='update_note_and_task:note_id', value=json.dumps(update_note_and_task__note_id))
    update_note_response(container=container)

    return

def get_current_user_settings(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_current_user_settings() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_current_user_settings' call
    formatted_data_1 = phantom.get_format_data(name='user_url_format')

    parameters = []
    
    # build parameters list for 'get_current_user_settings' call
    parameters.append({
        'headers': "",
        'location': formatted_data_1,
        'verify_certificate': False,
    })

    phantom.act(action="get data", parameters=parameters, assets=['phantom_rest_api'], callback=validate_confidence_level, name="get_current_user_settings")

    return

def user_url_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('user_url_format() called')
    
    template = """ph_user/{0}"""

    # parameter list for template variable replacement
    parameters = [
        "in_process_task_body:custom_function:owner",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="user_url_format")

    get_current_user_settings(container=container)

    return

def failure_or_SLA_violation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('failure_or_SLA_violation() called')

    phantom.comment(container=container, comment="Playbook failed or SLA expired. Please complete manually.")

    return

def get_analysis_task(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_analysis_task() called')

    # collect data for 'get_analysis_task' call
    formatted_data_1 = phantom.get_format_data(name='workbook_task_url')

    parameters = []
    
    # build parameters list for 'get_analysis_task' call
    parameters.append({
        'headers': "",
        'location': formatted_data_1,
        'verify_certificate': False,
    })

    phantom.act(action="get data", parameters=parameters, assets=['phantom_rest_api'], callback=check_for_tasks, name="get_analysis_task")

    return

"""
Review django url for "Indicator Analysis". This playbook supports this task.
"""
def workbook_task_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('workbook_task_url() called')
    
    template = """/workbook_task/?_filter_container={0}&_filter_name__startswith=\"Indicator analysis\"&_filter_status__in=[0,2]&sort=order&order=asc&page_size=1"""

    # parameter list for template variable replacement
    parameters = [
        "container:id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="workbook_task_url")

    get_analysis_task(container=container)

    return

def check_for_tasks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_for_tasks() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_analysis_task:action_result.data.*.response_body.data.*.status", "==", 0],
            ["get_analysis_task:action_result.data.*.response_body.data.*.status", "==", 2],
        ],
        logical_operator='or')

    # call connected blocks if condition 1 matched
    if matched:
        in_process_task_body(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    all_tasks_started(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def all_tasks_started(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('all_tasks_started() called')

    phantom.comment(container=container, comment="There no Indicator Analysis task to update notes for. Please review the parameter and playbook if this is in error.")

    return

"""
updates task, but you need to remove json.loads() to execute correctly. As the object is not passed correctly to the action.
"""
def update_task_to_inprocess(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_task_to_inprocess() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    in_process_task_body__task_body = phantom.get_run_data(key='in_process_task_body:task_body')
    # collect data for 'update_task_to_inprocess' call
    formatted_data_1 = phantom.get_format_data(name='task_url_format')

    parameters = []
    
    # build parameters list for 'update_task_to_inprocess' call
    parameters.append({
        'body': in_process_task_body__task_body,
        'headers': "",
        'location': formatted_data_1,
        'verify_certificate': False,
    })

    phantom.act(action="post data", parameters=parameters, assets=['phantom_rest_api'], callback=user_url_format, name="update_task_to_inprocess")

    return

"""
removed the json.loads() to keep the data a string as the rest api needs
"""
def update_task(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_task() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    update_note_and_task__task_body = phantom.get_run_data(key='update_note_and_task:task_body')
    # collect data for 'update_task' call
    formatted_data_1 = phantom.get_format_data(name='task_url_format')

    parameters = []
    
    # build parameters list for 'update_task' call
    parameters.append({
        'location': formatted_data_1,
        'body': update_note_and_task__task_body,
        'headers': "",
        'verify_certificate': False,
    })

    phantom.act(action="post data", parameters=parameters, assets=['phantom_rest_api'], name="update_task", parent_action=action)

    return

def update_note_response(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_note_response() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    update_note_and_task__note_body = json.loads(phantom.get_run_data(key='update_note_and_task:note_body'))
    update_note_and_task__note_id = json.loads(phantom.get_run_data(key='update_note_and_task:note_id'))
    # collect data for 'update_note_response' call

    parameters = []
    
    # build parameters list for 'update_note_response' call
    for index, note_params in enumerate(update_note_and_task__note_body):
        parameters.append({
            'body': json.dumps(note_params),
            'headers': "",
            'location': "/note/" + str(update_note_and_task__note_id[index]),
            'verify_certificate': False,
        })

    phantom.act(action="post data", parameters=parameters, assets=['phantom_rest_api'], callback=update_task, name="update_note_response")

    return

def validate_threat_level(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('validate_threat_level() called')
    
    # Set user and message variables for phantom.prompt call
    # Gets the current username for the playbook to assign the prompt correctly
    user_info = phantom.collect2(container=container, datapath=['get_current_user_settings:action_result.data.*.response_body.username', 'get_current_user_settings:action_result.data.*.response_body.first_name'], action_results=results)
    #phantom.debug(user_info)
    
    # Assigns the username for prompt assignment
    user = user_info[0][0]
    first_name = user_info[0][1]
    
    # Gets the note data to loop thru and set the title for 
    note_data = phantom.collect2(container=container, datapath=['get_analysis_task:action_result.data.*.response_body.data.*.notes'], action_results=results)[0][0]
    #phantom.debug(note_data)
    
    # Called out for using append() function for loop
    response_types = [{
            "prompt": "Analyst's Threat Level Comments:",
            "options": {
                "type": "message",
            },
        },
    ]
    title = ""
    
    # Loops thru notes and parses out indicator and title for use in message and prompt
    for note in note_data:
        if not note['title'].startswith("Automated "):
            title += note["title"] + '\n\r'
            indicator = re.search('Indicator: (.*?)\|', note['title']).group(1).strip()
            phantom.debug("Processing prompt for indicator: {}".format(indicator))

            #responses:
            response_types.append({
                "prompt": indicator,
                "options": {
                    "type": "list",
                    "choices": [
                        "Critical",
                        "High",
                        "Medium",
                        "Low",
                    ]
                },
            }
            )

    message = """{}, 
Please take time to review the Note:\n\r {}
Determine the Indicator Threat Level for up to 20 indicators presented.

Please see the task description for any additional details on this task.""".format(first_name,title)
    
    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="validate_threat_level", response_types=response_types, callback=determine_threat_type)

    return

def determine_threat_type(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('determine_threat_type() called')
    
    # Set user and message variables for phantom.prompt call
    # Gets the current username for the playbook to assign the prompt correctly
    user_info = phantom.collect2(container=container, datapath=['get_current_user_settings:action_result.data.*.response_body.username', 'get_current_user_settings:action_result.data.*.response_body.first_name'], action_results=results)
    #phantom.debug(user_info)
    
    # Assigns the username for prompt assignment
    user = user_info[0][0]
    first_name = user_info[0][1]
    
    # Gets the note data to loop thru and set the title for 
    note_data = phantom.collect2(container=container, datapath=['get_analysis_task:action_result.data.*.response_body.data.*.notes'], action_results=results)[0][0]
    #phantom.debug(note_data)
    
    # Called out for using append() function for loop
    response_types = [{
            "prompt": "Analyst's Threat Type Comments:",
            "options": {
                "type": "message",
            },
        },
    ]
    title = ""
    
    # Loops thru notes and parses out indicator and title for use in message and prompt
    for note in note_data:
        if not note['title'].startswith("Automated "):
            title += note["title"] + '\n\r'
            indicator = re.search('Indicator: (.*?)\|', note['title']).group(1).strip()
            phantom.debug("Processing prompt for indicator: {}".format(indicator))

            #responses:
            response_types.append({
                "prompt": indicator,
                "options": {
                    "type": "list",
                    "choices": [
                        "APT",
                        "Malware",
                        "Suspicious",
                        "Allowed",
                        "Undetermined",
                    ]
                },
            }
            )

    message = """{}, 
Please take time to review the Note:\n\r {}
Determine the Indicator Threat Type for up to 20 indicators presented.

Please see the task description for any additional details on this task.""".format(first_name,title)
    
    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="determine_threat_type", response_types=response_types, callback=evaluate_prompt)

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
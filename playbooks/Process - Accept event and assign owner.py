"""
This playbook assigns the event, "Review IOC Enrichment" task and close out the task as accepted.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'get_and_set_owner' block
    get_and_set_owner(container=container)

    return

def get_and_set_owner(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
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
    configure_container(container=container)

    return

def configure_container(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('configure_container() called')

    phantom.set_status(container=container, status="Open")

    phantom.add_tags(container=container, tags="IOCs")
    in_process_task_body(container=container)

    return

"""
use get_task() phantom api call
"""
def in_process_task_body(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('in_process_task_body() called')
    get_and_set_owner__owner = json.loads(phantom.get_run_data(key='get_and_set_owner:owner'))

    in_process_task_body__task_body = None
    in_process_task_body__task_id = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    """ Task status [ 0 = Incomplete, 2 = In Progress, 1 = Complete]"""
    # Get tasks and update task body
    task_data = {}
    in_process_task_body__task_body = []
    task_body = {}
    for task in phantom.get_tasks(container=container):
        #phantom.debug(task)
        if task["data"]["name"] == "Review IOC Enrichment":
            task_data = task["data"]
            #phantom.debug(task_data)

    # Assign new attributes to task body
    if task_data:
        # Set owner
        in_process_task_body__task_body.append({
            'owner': get_and_set_owner__owner,
            'is_note_required': False,
            'status' : 2
        })        

    in_process_task_body__task_id = task_data["id"]
    #phantom.debug(in_process_task_body__task_body)
    #phantom.debug(in_process_task_body__task_id)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='in_process_task_body:task_body', value=json.dumps(in_process_task_body__task_body))
    phantom.save_run_data(key='in_process_task_body:task_id', value=json.dumps(in_process_task_body__task_id))
    task_url_format(container=container)

    return

def task_url_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('task_url_format() called')
    
    template = """/workflow_task/{0}"""

    # parameter list for template variable replacement
    parameters = [
        "in_process_task_body:custom_function:task_id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="task_url_format")

    updates_in_process_task(container=container)

    return

"""
removed the json.loads() to keep the data a string as the rest api needs
"""
def updates_in_process_task(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('updates_in_process_task() called')

    in_process_task_body__task_body = json.loads(phantom.get_run_data(key='in_process_task_body:task_body'))
    # collect data for 'updates_in_process_task' call
    formatted_data_1 = phantom.get_format_data(name='task_url_format')

    parameters = []
    
    # build parameters list for 'updates_in_process_task' call
    for task_body in in_process_task_body__task_body:
        parameters.append({
            'body': json.dumps(task_body),
            'headers': "",
            'location': formatted_data_1,
            'verify_certificate': False,
        })

    phantom.act("post data", parameters=parameters, assets=['phantom rest api'], callback=complete_task_body, name="updates_in_process_task")

    return

def complete_task_body(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('complete_task_body() called')
    get_and_set_owner__owner = json.loads(phantom.get_run_data(key='get_and_set_owner:owner'))

    complete_task_body__task_body = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    """ Task status [ 0 = Incomplete, 2 = In Progress, 1 = Complete]"""
    # Get tasks and update task body
    task_data = {}
    complete_task_body__task_body = []
    task_body = {}
    for task in phantom.get_tasks(container=container):
        #phantom.debug(task)
        if task["data"]["name"] == "Review IOC Enrichment":
            task_data = task["data"]
            #phantom.debug(task_data)

    # Assign new attributes to task body
    if task_data:
        # Set owner
        complete_task_body__task_body.append({
            'owner': get_and_set_owner__owner,
            'is_note_required': False,
            'status' : 1
        })        

    #phantom.debug(complete_task_body__task_body)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='complete_task_body:task_body', value=json.dumps(complete_task_body__task_body))
    update_complete_task(container=container)

    return

def update_complete_task(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('update_complete_task() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    complete_task_body__task_body = json.loads(phantom.get_run_data(key='complete_task_body:task_body'))
    # collect data for 'update_complete_task' call
    formatted_data_1 = phantom.get_format_data(name='task_url_format')

    parameters = []
    
    # build parameters list for 'update_complete_task' call
    for task_body in complete_task_body__task_body:
        parameters.append({
            'location': formatted_data_1,
            'body': json.dumps(task_body),
            'headers': "",
            'verify_certificate': False,
        })

    phantom.act("post data", parameters=parameters, assets=['phantom rest api'], name="update_complete_task")

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all detals of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return
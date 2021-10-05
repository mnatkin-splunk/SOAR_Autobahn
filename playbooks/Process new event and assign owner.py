"""
This playbook assigns the event with the current phase first task in the current phase, close the task as completed and run the next playbook in the next task.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
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
    configure_container(container=container)

    return

def configure_container(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('configure_container() called')

    phantom.set_status(container=container, status="Open")
    task_update(container=container)

    return

"""
use get_phase() and  get_task() phantom api calls to update response plan
"""
def task_update(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('task_update() called')
    
    input_parameter_0 = "Accept and assign event"
    get_and_set_owner__owner = json.loads(phantom.get_run_data(key='get_and_set_owner:owner'))

    task_update__task_body = None
    task_update__task_id = None
    task_update__next_playbook = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    # Get the current phase
    #success, message, phase_id, phase_name = phantom.get_phase()

    #phantom.debug('phantom.get_phase results: success: {}, message: {}, phase_id: {}, phase_name: {}'.format(success, message, phase_id, phase_name))

    # Define task body for updating task. 
    """ Task status [ 0 = Incomplete, 2 = In Progress, 1 = Complete]"""
    task_body = {
        "owner": get_and_set_owner__owner,
        "is_note_required" : False,
        "status" : 2
    }
    
    task_data = {}
    next_task = {}
    
    # Get the tasks for start of the workbook
    for task in phantom.get_tasks(container=container):
        ## gets the current phase and 1st task
        if task['data']['name'] == input_parameter_0:
            task_data.update(task['data'])
            phantom.debug('phantom.get_tasks found the first task: task_id: {}, task_name: {}'.format(task_data['id'],task_data['name']))
    #phantom.debug(task_data)
    
    # get the next task in the order
    for task in phantom.get_tasks(container=container):
        ## gets the next task in the order
        if task_data['phase'] == task['data']['phase'] and task['data']['order'] == (task_data['order'] +1):
            next_task.update(task['data'])
            phantom.debug('phantom.get_tasks found the next task: task_id: {}, task_name: {}'.format(next_task['id'],next_task['name']))

    # Assign new attributes to task body based on status
    """ Task status [ 0 = Incomplete, 2 = In Progress, 1 = Complete]"""
    if task_data['status'] == 0 or task_data['status'] == 2:
        # Set owner and status
        task_update__task_body = task_body
        task_update__task_id = task_data["id"]
        phantom.debug("finished finding the task body for id: {} and saving.".format(task_update__task_id))
        ## checks next task for playbook data to call
        try:
            task_update__next_playbook = "{}/{}".format(next_task['suggestions']['playbooks'][0]['scm'],next_task['suggestions']['playbooks'][0]['playbook'])
            phantom.debug("Found the following next playbook to launch: {}".format(task_update__next_playbook))
        except:
            phantom.debug('Next task data does not have playbook to call.')         
    else:
        phantom.error('Task data status is completed and will not be modified')
    
    """ Debug statements
    phantom.debug(task_update__task_body)
    phantom.debug(task_update__task_id)
    phantom.debug(task_update__next_playbook)"""

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='task_update:task_body', value=json.dumps(task_update__task_body))
    phantom.save_run_data(key='task_update:task_id', value=json.dumps(task_update__task_id))
    phantom.save_run_data(key='task_update:next_playbook', value=json.dumps(task_update__next_playbook))
    task_url_format(container=container)

    return

def task_url_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('task_url_format() called')
    
    template = """/workflow_task/{0}"""

    # parameter list for template variable replacement
    parameters = [
        "task_update:custom_function:task_id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="task_url_format")

    check_task_body(container=container)

    return

"""
removed the json.loads() to keep the data a string as the rest api needs from the custom function block

revised code: line 146
task_update__task_body = phantom.get_run_data(key='task_update:task_body')
"""
def update_task_to_inprocess(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_task_to_inprocess() called')

    task_update__task_body = phantom.get_run_data(key='task_update:task_body')
    # collect data for 'update_task_to_inprocess' call
    formatted_data_1 = phantom.get_format_data(name='task_url_format')

    parameters = []
    
    # build parameters list for 'update_task_to_inprocess' call
    parameters.append({
        'location': formatted_data_1,
        'body': task_update__task_body,
        'headers': "",
        'verify_certificate': False,
    })

    phantom.act(action="post data", parameters=parameters, assets=['phantom_rest_api'], callback=task_complete, name="update_task_to_inprocess")

    return

def task_complete(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('task_complete() called')
    
    task_update__task_body = json.loads(phantom.get_run_data(key='task_update:task_body'))

    task_complete__task_body = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    """ Task status [ 0 = Incomplete, 2 = In Progress, 1 = Complete]"""
    # Updates task body for task completed
    task_update__task_body['status'] = 1
    task_complete__task_body = task_update__task_body
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='task_complete:task_body', value=json.dumps(task_complete__task_body))
    update_task_to_complete(container=container)

    return

"""
removed the json.loads() to keep the data a string as the rest api needs from the custom function block
"""
def update_task_to_complete(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_task_to_complete() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    task_complete__task_body = phantom.get_run_data(key='task_complete:task_body')
    # collect data for 'update_task_to_complete' call
    formatted_data_1 = phantom.get_format_data(name='task_url_format')

    parameters = []
    
    # build parameters list for 'update_task_to_complete' call
    parameters.append({
        'body': task_complete__task_body,
        'headers': "",
        'location': formatted_data_1,
        'verify_certificate': False,
    })

    phantom.act(action="post data", parameters=parameters, assets=['phantom_rest_api'], name="update_task_to_complete")

    return

def check_task_body(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_task_body() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["task_update:custom_function:task_body", "==", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        completed_task(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    update_task_to_inprocess(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def completed_task(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('completed_task() called')

    phantom.comment(container=container, comment="The task is completed, please run the next playbook in the task manually.")

    return

def add_new_processes_here(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_new_processes_here() called')
    
    task_complete(container=container)

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
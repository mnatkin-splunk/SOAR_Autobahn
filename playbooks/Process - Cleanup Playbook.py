"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

##############################
# Start - Global Code Block

from datetime import timedelta

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'get_data_1' block
    get_data_1(container=container)

    return

def get_data_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('get_data_1() called')

    # collect data for 'get_data_1' call

    parameters = []
    
    now = datetime.now()
    
    now = now
    
    one_day_ago = now - timedelta(days=1)
    
    # build parameters list for 'get_data_1' call
    parameters.append({
        'location': "/container?_filter_status=1&page_size=0&_filter_create_time__gt=\"{}\"&_filter_create_time__lt=\"{}\"".format(one_day_ago.strftime('%Y-%m-%dT00:00:00'), now.strftime('%Y-%m-%dT00:00:00')),
        'verify_certificate': False,
        'headers': "",
    })

    phantom.act("get data", parameters=parameters, assets=['phantom app'], callback=post_data_2, name="get_data_1")

    return

def post_data_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('post_data_2() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'post_data_2' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_data_1:action_result.data.*.response_body.data.*.id', 'get_data_1:action_result.parameter.context.artifact_id'], action_results=results)
    
    phantom.debug(results_data_1)
    
    parameters = []
    
    # build parameters list for 'post_data_2' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'location': '/container/{}'.format(results_item_1[0]),
                'body': "{\"status\":\"open\"}",
                'headers': "",
                'verify_certificate': False,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act("post data", parameters=parameters, assets=['phantom app'], name="post_data_2", callback=get_data_2, parent_action=action)

    return

def get_data_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('get_data_2() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_data_2' call

    now = datetime.now()
    
    now = now
    
    one_day_ago = now - timedelta(days=1)
    parameters = []
    # build parameters list for 'get_data_1' call
    parameters.append({
        'location': "/container?page_size=0&_filter_status__lt=3&_filter_create_time__lt=\"{}\"".format(one_day_ago.strftime('%Y-%m-%dT00:00:00')),
        'verify_certificate': False,
        'headers': "",
    })

    phantom.act("get data", parameters=parameters, assets=['phantom app'], name="get_data_2", callback=post_data_3, parent_action=action)

    return

def post_data_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('post_data_3() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'post_data_3' call
    # collect data for 'post_data_2' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_data_2:action_result.data.*.response_body.data.*.id', 'get_data_2:action_result.parameter.context.artifact_id'], action_results=results)
    
    phantom.debug(results_data_1)
    
    parameters = []
    
    # build parameters list for 'post_data_2' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'location': '/container/{}'.format(results_item_1[0]),
                'body': "{\"status\":\"closed\"}",
                'headers': "",
                'verify_certificate': False,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act("post data", parameters=parameters, assets=['phantom app'], callback=get_data_3, name="post_data_3", parent_action=action)

    return

def get_data_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('get_data_3() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_data_3' call

    now = datetime.now()
    
    now = now
    
    thirty_day_ago = now - timedelta(days=30)
    
    parameters=[]
    
    # build parameters list for 'get_data_1' call
    parameters.append({
        'location': "/container?page_size=0&_filter_label__iregex=\"^((?!Demo_Configuration).)*$\"&_filter_create_time__lt=\"{}\"".format(thirty_day_ago.strftime('%Y-%m-%dT00:00:00')),
        'verify_certificate': False,
        'headers': "",
    })

    phantom.act("get data", parameters=parameters, assets=['phantom app'], callback=delete_data_1, name="get_data_3", parent_action=action)

    return

def delete_data_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('delete_data_1() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['get_data_3:action_result.data.*.response_body.data.*.id', 'get_data_3:action_result.parameter.context.artifact_id'], action_results=results)
    
    phantom.debug(results_data_1)
    
    parameters = []
    
    # build parameters list for 'post_data_2' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'location': '/container/{}'.format(results_item_1[0]),
                'headers': "",
                'verify_certificate': False,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act("delete data", assets=['phantom app'], parameters=parameters, name="delete_data_1", parent_action=action)

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
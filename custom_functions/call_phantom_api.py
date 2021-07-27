def call_phantom_api_py3(**kwargs):
    """
    Checks if certain Phantom APIs are callable.
    
    Returns a JSON-serializable object that implements the configured data paths:
        status (CEF type: int)
        success (CEF type: int)
        fail (CEF type: int)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import traceback
    import phantom.rules as phantom
    
    outputs = {
        'status': True,
        'success': 0,
        'fail': 0,
    }
    
    # Write your custom code here
    functions_to_run = {
        'act': {
            'function': phantom.act,
            'args': ["totally_valid_action_name"],
            'kwargs': {},
        },
        'check_list': {
            'function': phantom.check_list,
            'args': ['valid_listname', 'valid_value'],
            'kwargs': {},
            'check': 'check_tuple_false',
        },
        'clear_object': {
            'function': phantom.clear_object,
            'args': ['some_key', 1],
            'kwargs': {},
            'check': 'check_none',
        },
        'completed': {
            'function': phantom.completed,
            'args': [['valid_action_name'], ['valid_playbook_name']],
            'kwargs': {},
        },
        'condition': {  # Condition fails immediately
            'function': phantom.condition,
            'args': [],
            'kwargs': {},
        },
        'custom_function': {
            'function': phantom.custom_function,
            'args': ["totally_valid_cf"],
            'kwargs': {
                "name": "my_totally_valid_cf"
            }
        },
        'decision': {  # Decision Fails immediately
            'function': phantom.decision,
            'args': [],
            'kwargs': {},
        },
        'discontinue': {
            'function': phantom.discontinue,
            'args': [],
            'kwargs': {},
        },
        'get_apps': {
            'function': phantom.get_apps,
            'args': ['string', 'string', 'string'],
            'kwargs': {},
        },
        'get_assets': {
            'function': phantom.get_assets,
            'args': ['string', ['tags'], ['types']],
            'kwargs': {},
        },
        'get_data': {
            'function': phantom.get_data,
            'args': ['some_key'],
            'kwargs': {},
        },
        'get_extra_data': {
            'function': phantom.get_extra_data,
            'args': ['some_action', 1, 1],
            'kwargs': {},
        },
        'get_object': {
            'function': phantom.get_object,
            'args': [],
            'kwargs': {
                'key': 'valid_key',
                'container_id': 1
            },
            'check': 'check_none',
        },
        'get_raw_data': {
            'function': phantom.get_raw_data,
            'args': [{'id': 1}],
            'kwargs': {},
        },
        'get_summary': {
            'function': phantom.get_summary,
            'args': [],
            'kwargs': {},
        },
        'playbook': {
            'function': phantom.playbook,
            'args': [],
            'kwargs': {
                "playbook": "totally_valid_playbook",
                "container": {
                    "id": 0, 
                }
            },
        },
        'prompt': {
            'function': phantom.prompt,
            'args': [],
            'kwargs': {
                'user': 'totally_valid_user',
            },
        },
        'prompt2': {
            'function': phantom.prompt2,
            'args': [],
            'kwargs': {
                'user': 'totally_valid_user',
                'response_types': [{'prompt': 'totally_valid_response_value'}],
            },
        },
        'save_data': {
            'function': phantom.save_data,
            'args': ['some_value'],
            'kwargs': {},
        },
        'save_object': {
            'function': phantom.save_object,
            'args': [],
            'kwargs': {
                'key': 'some_key',
                'value': 'some_value',
                'container_id': 1
            },
            'check': 'check_none',
        },
        'save_run_data': {
            'function': phantom.save_run_data,
            'args': ['totally_valid_value'],
            'kwargs': {},
        },
        'set_action_limit': {
            'function': phantom.set_action_limit,
            'args': [9001],
            'kwargs': {},
        },
        'set_parent_handle': {
            'function': phantom.set_parent_handle,
            'args': ['totally_valid_handle'],
            'kwargs': {},
            'check': 'check_none',
        },
        'task': {
            'function': phantom.task,
            'args': ['totally_valid_user', 'totally_valid_message'],
            'kwargs': {},
        },
    }
    
    for key in list(functions_to_run.keys()):
        # Avoiding iteritems() to avoid py2/py3 collision
        function_dict = functions_to_run[key]
        try:
            value = function_dict['function'](*function_dict['args'], **function_dict['kwargs'])
        except RuntimeError as e:
            phantom.debug("{}".format(e))
            outputs['success'] += 1
        except Exception as e:
            phantom.error("{} Did not raise RuntimeException".format(key))
            phantom.error("{}".format(e))
            phantom.error(traceback.format_exc())
            outputs['fail'] += 1
        else:
            check_type = function_dict.get('check')
            if check_type is None:
                phantom.error("{} Did not raise RuntimeException".format(key))
                outputs['fail'] += 1
            elif check_type == "check_none" and value is None:
                outputs['success'] += 1
            elif check_type == "check_false" and value is False:
                outputs['success'] += 1
            elif check_type == "check_tuple_false" and value[0] is False:
                outputs['success'] += 1
            else:
                phantom.error("{} did not return type {}".format(key, check_type))
                outputs['fail'] += 1
            
    if outputs['fail']:
        outputs['status'] = False
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
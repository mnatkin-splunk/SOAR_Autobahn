def POV_get_current_task_py3(container=None, currentOwner=None, **kwargs):
    """
    Gets the current task in the phase, and returns the task_id, and current owner of the playbook
    
    Args:
        container (CEF type: *)
        currentOwner (CEF type: *)
    
    Returns a JSON-serializable object that implements the configured data paths:
        task_body (CEF type: *)
        task_id (CEF type: *)
        next_playbook (CEF type: *)
        workflow_task_url (CEF type: *)
        status (CEF type: *)
        message (CEF type: *)
        task_name (CEF type: *): Name of the Task in the workbook
        current_playbook_name (CEF type: *): This Playbook Executing Now.
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Define task body for updating task. 
    """ Task status [ 0 = Incomplete, 2 = In Progress, 1 = Complete]"""
    task_body = {
        "owner" : currentOwner[0],
        "is_note_required" : False,
        "status" : 2
    }
    
    # Get the current playbook info
    current_playbook = phantom.get_playbook_info()
    current_playbook_name = current_playbook[0]['name']
    
    
    # Get the current phase
    success, message, phase_id, phase_name = phantom.get_phase()
    phantom.debug('[+] get_phase (current phase) returns: {0}, {1}, {2}, {3}'.format(success,message,phase_id, phase_name))
    
    # If no phase has been set yet - set it - and try again
    if phase_id == None:
        try:
            phantom.debug("[+] No phase set yet - Attempting to set it")
            params={
                'sort':'order',
                'order':'asc'
            }
            phase_url = phantom.build_phantom_rest_url('container', container[0], 'phases')
            response = phantom.requests.get(phase_url, params=params,verify=False)
            # if count > 0 then workbook has been attached
            if response.json()['count'] > 0:
                phase_name = response.json()['data'][0]['name']
                success, message = phantom.set_phase(phase=phase_name)
                success, message, phase_id, phase_name = phantom.get_phase()
                phantom.debug('phantom.get_phase results: success: {}, message: {}, phase_id: {}, phase_name: {}'.format(success, message, phase_id, phase_name))
            else:
                phantom.error('[+] No workbook attached to container')
                outputs = {'status': 'failed', 'message': 'No workbook attached to container'}
                return outputs
        except:
            phantom.error('[+] Cannot Access REST API - Unable to take ownership')
            outputs = {'status': 'failed', 'message': 'Failed to access rest api'}
            return outputs
        
        
    # Check if this playbook has ran against this container previously. It could be a re-run - therefore we need to set the task status
    # back to 'Not Started' so as we get the right current task below.
    # The limitation here is a playbook can only be only be ran once against a workbook. (POV_Accept_Event - once per workbook)
    try:
        phantom.debug('[+] Checking for previous playbook runs for this container')
        url = phantom.build_phantom_rest_url('playbook_run')
        params = {
            '_filter_container': container[0],
            '_filter_playbook': current_playbook[0]['id']
            
        }
        
        response = phantom.requests.get(url, params=params, verify=False)
        r = response.json()
        phantom.debug('[+] getting URL: {0} returned: {1}'.format(url,r))
        pb_runs = r['data']
        phantom.debug('[+] Got {} previous runs of this playbook'.format(len(pb_runs)))
        if len(pb_runs) > 0:
            phantom.debug('[+] Fetching COMPLETED tasks associated with this playbook')
            params = {
                '_filter_container_id' : container[0], 
                '_filter_status': 1,
                '_filter_phase': phase_id
            }
            
            url = phantom.build_phantom_rest_url('workflow_task')
            response = phantom.requests.get(url, params=params, verify=False)
            r = response.json()
            rtasks = r['data']
            phantom.debug('[+] Number of completed tasks brought back (ANY PLAYBOOK) : {}'.format(len(rtasks)))

            reverting_task = None
            for i, task in enumerate(rtasks):
                try:
                    playbook_for_task= task['suggestions']['playbooks'][0]['playbook']
                except:
                    continue
                
                if current_playbook_name == playbook_for_task:
                    phantom.debug('[+] Matched - This playbook has previous ran against task id: {0}, task: {1}'.format(task['id'],task['name']))
                    task_id = task['id']
                    params = {
                        'status': 0   
                    }
                    url = phantom.build_phantom_rest_url('workflow_task', task_id)
                    phantom.debug('[+] Attempting to reset the status to not started')
                    reverting_task = True
                    response = phantom.requests.post(url, json=params, verify=False)
                    if response: 
                        phantom.debug('[+] Status reverted back - continuing.')
                    else: 
                        outputs = {'status': 'failed', 'message': 'Failed to set status to not started, for duplicated PB run'}
                        return outputs
            
            if not reverting_task:
                phantom.debug('[+] No tasks found to revert')
                    
    except Exception as err:
        phantom.error('Unable to figure out previous run information: {}'.format(err))
    
    task_data = {}
    next_task = {}
    task_id = None
    next_playbook = None
    
    if phase_id:
        params = {
            '_filter_phase_id': phase_id,
            '_filter_container_id': container[0],
            '_filter_status': 0,
            'sort': 'order',
            'order': 'asc',
            'page_size': '2'
        }
        #Fetch all tasks for this phase
        try:
            url = phantom.build_phantom_rest_url('workflow_task')
            response = phantom.requests.get(url,params=params, verify=False)
            resp = response.json()
            tasks = resp['data']
            phantom.debug('[+] Attempting to determined the current task and next tasks')
            phantom.debug('[+] There are {0} remaining NOT STARTED tasks in the tasks list for phase: {1}'.format(len(tasks), phase_name))
            
        except:
            phantom.error('[+] Failed to fetch tasks')
            outputs = {'status': 'failed', 'message': 'Unable to get url: {}'.format(url)}
            return outputs
        
        for i, task in enumerate(tasks):
            phantom.debug('[+] Checking Current Task: {}'.format(task['name']))
            phantom.debug('[+] whole task {}'.format(tasks[0]))
            if len(tasks) > 1:
                phantom.debug('[+] whole NEXT task {}'.format(tasks[1]))
            
            if phase_id == task['phase'] and task['status'] == 0:
                # We have found the first 'not started' task in this phase
                # and therefore the next task to start
                task_order = task['order']
                previous_task_order = task_order - 1
                next_task_order = task_order + 1
                phantom.debug('[+] FOUND a match: calculated task_order as: {0} and previous_task as: {1}, next task as: {2}'.format(task_order,previous_task_order,next_task_order))
                
                # Now go looking for order - 1 - i.e the current in-progress or completed task
                #for task in phantom.get_tasks(container):
                params['_filter_status'] = 1
                params['order'] = "desc"
                params['page_size'] = 1
                
                # Get the last task marked as complete - if the tasks have been completed sequentially - the order should be task_order-1
                # Do this only if the current task is not the first task
                if task_order > 1:
                    phantom.debug('[+] FETCHING Last Completed Task to make sure it is marked as completed.')
                    try:
                        response = phantom.requests.get(url,params=params, verify=False)
                        resp_prev = response.json()
                        prev_tasks = resp_prev['data']
                        phantom.debug('[+] Fetched {} previous tasks'.format(len(prev_tasks)))
                    except:
                        phantom.error('[+] Failed to FETCH previous task')
                        outputs = {'status': 'failed', 'message': 'Unable to get url: {}'.format(url)}
                        return outputs
                    
                    if len(prev_tasks) == 0:
                        phantom.debug('[+] No previously completed tasks found. - Check previous tasks and mark complete')
                        phantom.comment(comment='No previously completed tasks found. - Check previous tasks and mark complete')
                        outputs = {'status': 'failed', 'message': 'No previously completed tasks found.'}
                        return outputs
                        
            
                    for prev_task in prev_tasks:
                        #phantom.debug('looking at previous task: {}'.format(prev_task))
                        phantom.debug('[+] Checking PREVIOUS COMPLETED Task : {0} with name {1} '.format(prev_task['order'],prev_task['name']))
                        if prev_task['order'] != previous_task_order:
                            #Tasks may be ran out of order - but I can't reliably detect the next task in sequence.
                            phantom.error('[+] Cannot locate next sequential task - complete previous tasks and try again')
                            phantom.comment(comment='Playbook cannot determined next tasks - mark previous tasks complete and try again')
                            outputs = {'status': 'failed', 'message': 'Cannot locate next sequential task - complete previous tasks and try again'}
                            return outputs
                        else:
                            phantom.debug("[+] Previous task: {} has been marked completed. - Moving on.".format(prev_task['name']))
                
                # Otherwise - we know the next task that needs to be worked on
                task_data.update(task)
                
                # Now understand what the next task looks like - to try and ascertain the next playbook that needs running.
                # Provided this is NOT the last task in the phase
                if len(tasks) > 1:
                    next_task = tasks[i+1]
                    if phase_id == next_task['phase']:
                        phantom.debug('[+] Next task is: {}'.format(next_task['name']))
                        phantom.debug('[+] Checking if there is a playbook associated: {}'.format(next_task['name']))
                        try:
                            next_playbook = "{}/{}".format(next_task['suggestions']['playbooks'][0]['scm'],next_task['suggestions']['playbooks'][0]['playbook'])
                        except: 
                            phantom.debug("No Associated Playbook found against task {}".format(next_task['name']))
                    
                        # if we detect the same playbook - we likely have an issue that previous tasks are not marked completed and/or not started.
                        if next_playbook is not None:
                            if current_playbook_name == next_task['suggestions']['playbooks'][0]['playbook']:
                                phantom.error('[+] Next Playbook detected as this playbook. Likely previous tasks are not started or incomplete')
                                phantom.comment(comment='Cannot determined the next playbook - check previous tasks are complete and try again')
                                outputs = {'status': 'failed', 'message': 'Cannot determined the next playbook - check previous tasks are complete and try again'}
                                return outputs
                    
                            phantom.debug('[+] Next playbook should be: {}'.format(next_playbook))
                    
                break
                

    workflow_url = phantom.build_phantom_rest_url("workflow_task", str(task_data['id']))
    phantom.debug("Setting task_id to: {}".format(task_data['id']))
    outputs = {
        'current_playbook_name': current_playbook_name,
        'task_body': task_body,
        'task_id': task_data['id'],
        'task_name':task_data['name'],
        'next_playbook': next_playbook,
        'workflow_task_url' : workflow_url,
        'status': 'success',
        'message': 'success'
    }
    
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs

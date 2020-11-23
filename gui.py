import PySimpleGUI as sg

def collab_suggests_refinement(graph_path, list_of_pkt_header_restrictions, list_of_refinement_methods,
                               config_file_text_list):
    '''
    :param graph_path: path to image file for graph
    :param list_of_pkt_header_restrictions: a list of strings (so must include the name of the relevant part of the
        packet header (e.g., src_ip) as well as the value for that part (e.g., x.x.x.x) in the string
    :param list_of_refinement_methods: lists to show the collaborator. each option will show up once in the list
    :param config_file_text_list: list of the text of the config files (so we can show them in tabs)
    :return: index of selected refinement method
    '''
    # this function is for asking the collaborator how to refine a network model
    # graph_path MUST be a gif file!

    print('list_of_refinement_methods', list_of_refinement_methods)

    table_headers = ['Root Cause', 'Responsible Node', 'Assumed desired path']
    main_tab_layout = [[sg.Text('Collaborator: Suggest Refinement Please')],
              [sg.Image(graph_path)],
              [sg.Text("Packet header constraints:")],
              [sg.Text("\n".join(list_of_pkt_header_restrictions))],
              [sg.Text('_'*30)],
              [sg.Text("Possible refinement approaches:")],
              [sg.Table(values=[list(i) for i in list_of_refinement_methods], display_row_numbers=True,
                        headings = table_headers, max_col_width=85, auto_size_columns=True)],
              #[sg.Text("\n".join(["; ".join(i) for i in list_of_refinement_methods] ))],
              [sg.Text('_' * 30)],
              [sg.Text('Which rows show the refinement method that you think should be attempted? (input the number)')],
              [sg.InputText(key='-IN-')],
              [sg.Submit(), sg.Cancel()]]

    tab_list = [[sg.Tab('Main Tab', main_tab_layout)]]

    #'''
    for index, config_file_text in enumerate(config_file_text_list):
        cur_tab_layout = [[sg.Text(config_file_text)]]
        tab_list.append( [sg.Tab('Config File: ' + str(index), cur_tab_layout)] )
    
    #print("Here's the layout object", layout)
    #'''

    layout = [ [sg.TabGroup( tab_list )] ]

    window = sg.Window('Window Title', layout)

    event, values = window.read()
    window.close()

    text_input = values['-IN-']
    sg.popup('You entered', text_input)

    return int(text_input), main_tab_layout

def collab_fixes_config_file(relevant_config_file_text, choices_tab_layout):
    # TODO: add the ability to see page where we explain the choices here...

    # purpose of this function is to display the config file to the user, so that they can fix it.
    # for now, we show the exact config file, let them edit it, and then save it (and recreate the model to check)
    main_tab_layout = [[sg.Text('Collaborator: Please fix this config file')],
                        [sg.Multiline(default_text=relevant_config_file_text, key='-IN-', size = (120, 50), enter_submits=False)],
                       [sg.Submit(), sg.Cancel()]]

    window = sg.Window('Window Title', main_tab_layout, font='Courier 14')

    event, values = window.read()
    window.close()

    text_input = values['-IN-']
    #sg.popup('You entered', text_input)
    return text_input

def user_says_if_fix_works(relevant_config_file_text, config_file_name, high_level_root_cause):
    table_headers = ['Root Cause', 'Responsible Node', 'Assumed desired path']
    main_tab_layout = [[sg.Text('Collaborator: Please fix this config file')],
                       [sg.Text('High-level root-cause: ' )],
                       [sg.Table(values=[high_level_root_cause], display_row_numbers=False,
                                 headings=table_headers, max_col_width=150, auto_size_columns=True)],
                       [sg.Text('Config file: ' + config_file_name)],
                       [sg.Multiline(default_text=relevant_config_file_text, key='-IN-', size=(120, 50),
                                     write_only=True)],
                       [sg.Text('--------')],
                       [sg.Text('--------')],
                       [sg.Text('Did the modified config file work?')],
                       [sg.Combo(['Yes', 'No'], key="-WORK-")],
                       [sg.Submit(), sg.Cancel()]]

    window = sg.Window('Window Title', main_tab_layout, font='Courier 14')

    event, values = window.read()
    window.close()

    text_input = values['-WORK-']
    if text_input == "Yes":
        problem_fixed = True
    elif text_input == "No":
        problem_fixed = False
    else:
        raise("How was this a text_input???")
    # sg.popup('You entered', text_input)
    print("text_input", problem_fixed)
    return text_input

def user_clarifies_refinement():
    pass

def collab_suggests_remediation():
    pass

def user_clarifies_remediation():
    pass

if __name__ == "__main__":
    graph_path = '/Users/jseverin/PycharmProjects/netivus_prototype/weighted_graph.gif'
    list_of_pkt_header_restrictions = ["src_ip: x.x.x.x", "dst_ip: x.x.x.x"]
    list_of_refinement_methods = ['1. Modify the model', '2. Adjust your attitude']
    config_file_text_list = ['this is a cisco router!', 'this is another brand of router!']

    #######################################
    #collab_suggests_refinement(graph_path, list_of_pkt_header_restrictions, list_of_refinement_methods, config_file_text_list)
    #collab_fixes_config_file('This is an example config file This is an example config file This is an example config file This is an example config file This is an example config filev', None)
    user_says_if_fix_works('This is an example config file This is an example config file This is an example config file This is an example config file This is an example config file', 'test_file.txt', ["need to polish the device", "dd", "ee"])
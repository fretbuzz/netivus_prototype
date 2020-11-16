import PySimpleGUI as sg

def collab_suggests_refinement(graph_path, list_of_pkt_header_restrictions, list_of_refinement_methods,
                               config_file_text_list):
    # this function is for asking the collaborator how to refine a network model
    # graph_path MUST be a gif file!

    main_tab_layout = [[sg.Text('Collaborator: Suggest Refinement Please')],
              [sg.Image(graph_path)],
              [sg.Text("Packet header constraints:")],
              [sg.Text("\n".join(list_of_pkt_header_restrictions))],
              [sg.Text('_'*30)],
              [sg.Text("Possible refinement approaches:")],
              [sg.Text("\n".join(list_of_refinement_methods))],
              [sg.Text('_' * 30)],
              [sg.Text('Which refinement method do you think should be attempted? (input the number)')],
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

    pass

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
    collab_suggests_refinement(graph_path, list_of_pkt_header_restrictions, list_of_refinement_methods, config_file_text_list)
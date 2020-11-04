import networkx as nx
import os, errno, math
import requests
import shutil
import json
import argparse
import ipaddress
import matplotlib.pyplot as plt

def plot_graph(G_layer_2, color_map, fig_number, title, show=True, layer_2=False, filename=None):
    fig = plt.figure(fig_number, figsize=(12, 12))
    fig.clf()
    ax = fig.add_subplot(111)
    #fig, ax = plt.subplots(1)
    margin = 0.44 #.33
    fig.subplots_adjust(margin, margin, 1. - margin, 1. - margin)
    plt.title(title)
    if layer_2:
        edge_labels = nx.get_edge_attributes(G_layer_2, 'access_vlan')
    else:
        edge_labels = nx.get_edge_attributes(G_layer_2, 'ip_address')

    node_labels = nx.get_node_attributes(G_layer_2, 'name')
    node_labels_description = nx.get_node_attributes(G_layer_2, 'description')
    for node,desc in node_labels_description.items():
        if desc is not None:
            node_labels[node] += '\n' + desc
    node_labels_node_type = nx.get_node_attributes(G_layer_2, 'type')
    for node,node_types in node_labels_node_type.items():
        if node_types is not None:
            node_labels[node] += '\n' + node_types
    num_nodes = G_layer_2.number_of_nodes()
    weight = 2.5/math.sqrt(num_nodes) # higher-weight -> edges are longer between connected nodes
    pos= nx.spring_layout(G_layer_2, k = weight)
    nx.draw(G_layer_2, pos=pos, node_color=color_map, with_labels=True, font_size=0, node_size=1200) #, edge_labels = edge_labels)
    nx.draw_networkx_edge_labels(G_layer_2, pos, edge_labels=edge_labels)
    nx.draw_networkx_labels(G_layer_2, pos, labels=node_labels)
    ###############
    # adding a textbox: https://matplotlib.org/3.1.1/gallery/recipes/placing_text_boxes.html
    textstr = 'Red: Devices\nGreen:Interfaces'
    props = dict(boxstyle='round', facecolor='wheat', alpha=0.5)
    ax.text(0.02, 0.98, textstr, transform=ax.transAxes, fontsize=5,
            verticalalignment='top', bbox=props)
    ##############
    #labels = nx.draw_networkx_labels(G, pos=nx.spring_layout(G))
    #plt.tight_layout()
    # now make the subplot size slightly larger...
    plt.draw()
    if filename is not None:
        plt.savefig(fname=filename)

    if show:
        plt.show()
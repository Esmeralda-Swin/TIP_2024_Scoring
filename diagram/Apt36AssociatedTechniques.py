import pandas as pd
import plotly.graph_objects as go
import networkx as nx

# Function to create an interactive network graph using Plotly
def create_apt_c36_network_techniques(df):
    # Identify techniques used by APT-C-36
    query_APT = df.loc[df['apt'] == 'APT-C-36', 'technique-id'].unique()
    related_apts = df[df['technique-id'].isin(query_APT)]['apt'].unique()[:5]

    # Create a graph
    G = nx.Graph()
    G.add_node('APT-C-36')

    # Add related APTs and their techniques
    for apt in related_apts:
        G.add_node(apt)
        G.add_edge('APT-C-36', apt)

        techniques = df.loc[df['apt'] == apt, 'technique-id'].unique()[:10]
        for technique in techniques:
            G.add_node(technique)
            G.add_edge(apt, technique)

    # Get node positions using spring layout
    pos = nx.spring_layout(G)

    # Extract node positions
    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.append(x0)
        edge_x.append(x1)
        edge_x.append(None)
        edge_y.append(y0)
        edge_y.append(y1)
        edge_y.append(None)

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.5, color='#888'),
        hoverinfo='none',
        mode='lines')

    # Extract node positions for each node
    node_x = []
    node_y = []
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        hoverinfo='text',
        textposition="top center",
        marker=dict(
            showscale=True,
            colorscale='YlGnBu',
            size=10,
            colorbar=dict(
                thickness=15,
                title='Node Connections',
                xanchor='left',
                titleside='right'
            ),
            line_width=2),
        text=[node for node in G.nodes()])

    # # Show number of connections for each node
    node_adjacency = []
    node_text = []
    for node, adjacency in G.adjacency():
        node_adjacency.append(len(adjacency))
        node_text.append(f"{node}")

    node_trace.marker.color = node_adjacency
    node_trace.text = node_text

    # Create the figure
    fig = go.Figure(data=[edge_trace, node_trace],
                    layout=go.Layout(
                        title='APT-C36 and Related Techniques',
                        titlefont_size=16,
                        showlegend=False,
                        hovermode='closest',
                        margin=dict(b=0, l=0, r=0, t=40),
                        annotations=[dict(
                            text="APT-C36 and related APTs/Techniques",
                            showarrow=False,
                            xref="paper", yref="paper")],
                        xaxis=dict(showgrid=False, zeroline=False),
                        yaxis=dict(showgrid=False, zeroline=False))
                    )

    return fig

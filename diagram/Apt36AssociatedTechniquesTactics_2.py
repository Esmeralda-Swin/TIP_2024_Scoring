import plotly.graph_objects as go
import networkx as nx

# Function to create an interactive network graph using Plotly
def create_apt_c36_network_techniques_tactics_2(df):
    # Identify techniques used by APT-C-36
    apt_36_techniques = df.loc[df['apt'] == 'APT-C-36', 'technique-id'].unique()

    # Find related APTs that use the same techniques
    related_apts = df[df['technique-id'].isin(apt_36_techniques)]['apt'].unique()

    # Limit to a maximum of 5 related APTs
    limited_related_apts = related_apts[:5]

    # Create a graph
    G = nx.Graph()
    G.add_node('APT-C-36', color='red')  # APT-C-36 in red

    # Add related APTs and their techniques
    for apt in limited_related_apts:
        G.add_node(apt, color='skyblue')  # Related APTs in skyblue
        G.add_edge('APT-C-36', apt)

        # Get associated techniques for the related APT
        techniques = df.loc[df['apt'] == apt, 'technique-id'].unique()

        # Limit the techniques to 5
        limited_techniques = techniques[:5]

        for technique in limited_techniques:
            G.add_node(technique, color='lightgreen')  # Techniques in lightgreen
            G.add_edge(apt, technique)

            # Get tactics associated with the technique
            tactics = df.loc[df['technique-id'] == technique, 'tactics'].dropna().unique()

            for tactic in tactics:
                if tactic:
                    G.add_node(tactic, color='orange')  # Tactics in orange
                    G.add_edge(technique, tactic)

    # Generate layout for positions of nodes
    pos = nx.spring_layout(G)

    # Create edge coordinates for Plotly
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
        mode='lines'
    )

    # Create node coordinates and attributes
    node_x = []
    node_y = []
    node_color = []
    node_text = []
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        node_color.append(G.nodes[node]['color'])
        node_text.append(f'{node}')

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        hoverinfo='text',
        textposition="top center",
        marker=dict(
            showscale=True,
            colorscale='YlGnBu',
            color=node_color,
            size=15,
            colorbar=dict(
                thickness=15,
                title='Node Connections',
                xanchor='left',
                titleside='right'
            ),
            line_width=2),
        text=node_text
    )

    # Create the interactive figure
    fig = go.Figure(data=[edge_trace, node_trace],
                    layout=go.Layout(
                        title='Interactive APT-C-36 Network',
                        titlefont_size=16,
                        showlegend=False,
                        hovermode='closest',
                        margin=dict(b=0, l=0, r=0, t=40),
                        annotations=[dict(
                            text="APT-C-36 and related APTs, Techniques, and Tactics",
                            showarrow=False,
                            xref="paper", yref="paper"
                        )],
                        xaxis=dict(showgrid=False, zeroline=False),
                        yaxis=dict(showgrid=False, zeroline=False)
                    )
    )
    return fig

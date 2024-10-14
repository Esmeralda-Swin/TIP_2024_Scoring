import networkx as nx
import plotly.graph_objects as go


def create_apt_network_techniques_tactics_cve(df, selected_apts):
    G = nx.Graph()

    # If no APTs are selected, default to adding APT-C-36
    if selected_apts is None or len(selected_apts) == 0:
        selected_apts = ['APT-C-36']  # Default to APT-C-36 if none selected

    # Ensure selected_apts is a list and handle single APT selection
    if isinstance(selected_apts, str):
        selected_apts = [selected_apts]  # Convert to list if a single APT is passed

    # Iterate over selected APTs
    for apt in selected_apts:
        G.add_node(apt, color='red')  # Selected APT in red

        # Identify techniques used by the selected APT
        selected_apt_techniques = df.loc[df['apt'] == apt, 'technique-id'].unique()

        # Add techniques associated with the selected APT
        for technique in selected_apt_techniques:
            G.add_node(technique, color='lightgreen')  # Techniques in lightgreen
            G.add_edge(apt, technique)  # Connect APT to its technique

            # Get tactics associated with the technique
            tactics = df.loc[df['technique-id'] == technique, 'tactics'].dropna().unique()  # Get unique tactics

            for tactic in tactics:
                if tactic:  # Check if the tactic is not empty
                    G.add_node(tactic, color='orange')  # Tactics in orange
                    G.add_edge(technique, tactic)  # Connect technique to its tactic

                    # Get CVEs associated with the technique
                    cves = df.loc[df['technique-id'] == technique, 'cve'].dropna().unique()  # Get unique CVEs

                    for cve in cves:
                        if cve:  # Check if the CVE is not empty
                            G.add_node(cve, color='purple')  # CVEs in purple
                            G.add_edge(tactic, cve)  # Connect tactic to its CVE

    # Get node positions using spring layout
    pos = nx.spring_layout(G)

    # Extract edge coordinates for Plotly
    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.append(x0)
        edge_x.append(x1)
        edge_x.append(None)  # Break line for Plotly
        edge_y.append(y0)
        edge_y.append(y1)
        edge_y.append(None)  # Break line for Plotly

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.5, color='#888'),
        hoverinfo='none',
        mode='lines'
    )

    # Extract node coordinates and attributes
    node_x = []
    node_y = []
    node_color = []
    node_text = []
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        node_color.append(G.nodes[node]['color'])
        node_text.append(f'{node}')  # Display the node name

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        hoverinfo='text',
        textposition="top center",
        marker=dict(
            showscale=False,  # Turn off the color scale
            color=node_color,
            size=15,
            line_width=2
        ),
        text=node_text
    )

    # Create the figure with edge and node traces
    fig = go.Figure(data=[edge_trace, node_trace],
                    layout=go.Layout(
                        title=f'{", ".join(selected_apts)} and Related Techniques, Tactics and CVE',
                        titlefont_size=16,
                        showlegend=False,
                        hovermode='closest',
                        margin=dict(b=0, l=0, r=0, t=40),
                        annotations=[dict(
                            text=f"{', '.join(selected_apts)}",
                            showarrow=False,
                            xref="paper", yref="paper"
                        )],
                        xaxis=dict(showgrid=False, zeroline=False),
                        yaxis=dict(showgrid=False, zeroline=False))
                    )

    return fig

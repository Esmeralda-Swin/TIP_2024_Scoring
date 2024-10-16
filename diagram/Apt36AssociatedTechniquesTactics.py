import networkx as nx
import plotly.graph_objects as go


def create_apt_network_techniques_tactics(df, selected_apts):
    G = nx.Graph()

    # If no APTs are selected, default to adding APT-C-36
    if selected_apts is None or len(selected_apts) == 0:
        G.add_node('APT-C-36', color='red')  # APT-C-36 in red
        # You may want to find related techniques and tactics for APT-C-36 here as well
        apt_c36_techniques = df.loc[df['apt'] == 'APT-C-36', 'technique-id'].unique()
        related_apts = df[df['technique-id'].isin(apt_c36_techniques)]['apt'].unique()

        # Limit to a maximum of 5 related APTs
        limited_related_apts = related_apts[:5]

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
                G.add_edge(apt, technique)  # Connect related APTs to their techniques

                # Get tactics associated with the technique
                tactics = df.loc[df['technique-id'] == technique, 'tactics'].dropna().unique()  # Get unique tactics

                for tactic in tactics:
                    if tactic:  # Check if the tactic is not empty
                        G.add_node(tactic, color='orange')  # Tactics in orange
                        G.add_edge(technique, tactic)  # Connect technique to its tactic

    else:
        # Ensure selected_apts is a list and handle single APT selection
        if isinstance(selected_apts, str):
            selected_apts = [selected_apts]  # Convert to list if a single APT is passed

        # Iterate over selected APTs
        for apt in selected_apts:
            # Identify techniques used by the selected APT
            selected_apt_techniques = df.loc[df['apt'] == apt, 'technique-id'].unique()

            # Find related APTs that use the same techniques
            related_apts = df[df['technique-id'].isin(selected_apt_techniques)]['apt'].unique()

            # Limit to a maximum of 5 related APTs
            limited_related_apts = related_apts[:5]

            G.add_node(apt, color='red')  # Selected APT in red

            # Add related APTs and their techniques
            for related_apt in limited_related_apts:
                G.add_node(related_apt, color='skyblue')  # Related APTs in skyblue
                G.add_edge(apt, related_apt)

                # Get associated techniques for the related APT
                techniques = df.loc[df['apt'] == related_apt, 'technique-id'].unique()

                # Limit the techniques to 5
                limited_techniques = techniques[:5]

                for technique in limited_techniques:
                    G.add_node(technique, color='lightgreen')  # Techniques in lightgreen
                    G.add_edge(related_apt, technique)  # Connect related APTs to their techniques

                    # Get tactics associated with the technique
                    tactics = df.loc[df['technique-id'] == technique, 'tactics'].dropna().unique()  # Get unique tactics

                    for tactic in tactics:
                        if tactic:  # Check if the tactic is not empty
                            G.add_node(tactic, color='orange')  # Tactics in orange
                            G.add_edge(technique, tactic)  # Connect technique to its tactic

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

    # Create the figure with edge and node traces
    fig = go.Figure(data=[edge_trace, node_trace],
                    layout=go.Layout(
                        title=f'{", ".join(selected_apts) if selected_apts else "APT-C-36"} and Related Techniques and Tactics',
                        titlefont_size=16,
                        showlegend=False,
                        hovermode='closest',
                        margin=dict(b=0, l=0, r=0, t=40),
                        annotations=[dict(
                            text=f"{', '.join(selected_apts) if selected_apts else 'APT-C-36'}",
                            showarrow=False,
                            xref="paper", yref="paper"
                        )],
                        xaxis=dict(showgrid=False, zeroline=False),
                        yaxis=dict(showgrid=False, zeroline=False))
                    )

    return fig

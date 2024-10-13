import pandas as pd
import plotly.graph_objects as go


def create_techniques_tactics_chart(df, selected_apts=None):
    # Apply APT filtering if selected_apts is provided
    if selected_apts:
        df = df[df['apt'].isin(selected_apts)]

    # Group by 'group' (APT Group) and count distinct techniques and tactics
    grouped_data = df.groupby('apt').agg(
        Distinct_Technique_Count=('technique-id', 'nunique'),
        Distinct_Tactic_Count=('subtechnique-name', 'nunique')  # Assuming subtechnique-name represents tactics
    ).reset_index()

    fig = go.Figure()

    # Add the bar for distinct techniques
    fig.add_trace(go.Bar(
        x=grouped_data['apt'],
        y=grouped_data['Distinct_Technique_Count'],
        name='Distinct Techniques',
        marker_color='blue'
    ))

    # Add the bar for distinct tactics stacked on top
    fig.add_trace(go.Bar(
        x=grouped_data['apt'],
        y=grouped_data['Distinct_Tactic_Count'],
        name='Distinct Tactics',
        marker_color='green'
    ))

    # Customize the layout of the stacked bar chart
    fig.update_layout(
        title='APT Groups with the Most Diverse Set of Techniques and Tactics',
        xaxis_title='APT Group',
        yaxis_title='Count of Distinct Techniques and Tactics',
        barmode='stack',
        xaxis_tickangle=-90
    )

    return fig

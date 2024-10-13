import plotly.graph_objects as go
import pandas as pd

def create_cwe_platform_heatmap(df, selected_cwes=None, selected_platforms=None):
    # Split platforms into separate rows
    df_expanded = df.assign(platform=df['platforms'].str.split(',')).explode('platform')

    # Remove any leading/trailing whitespace from platform names
    df_expanded['platform'] = df_expanded['platform'].str.strip()

    # Filter out rows with 'UNKNOWN' in the 'CWE-ID' column
    df_expanded = df_expanded[df_expanded['cwe-id'] != 'UNKNOWN']

    # Apply CWE filtering if selected
    if selected_cwes:
        df_expanded = df_expanded[df_expanded['cwe-id'].isin(selected_cwes)]

    # Apply platform filtering if selected
    if selected_platforms:
        df_expanded = df_expanded[df_expanded['platform'].isin(selected_platforms)]

    # Create a pivot table to count occurrences of each CWE per platform
    platform_cwe_pivot = df_expanded.pivot_table(index='platform', columns='cwe-id', aggfunc='size', fill_value=0)

    # Create the heatmap
    heatmap = go.Figure(go.Heatmap(
        z=platform_cwe_pivot.values,
        x=platform_cwe_pivot.columns,
        y=platform_cwe_pivot.index,
        colorscale='sunset'
    ))

    # Update the layout for titles and labels
    heatmap.update_layout(
        title='Heatmap of CWE Occurrences Across Platforms',
        xaxis_title='CWE-ID',
        yaxis_title='Platform'
    )

    return heatmap

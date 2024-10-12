import plotly.graph_objects as go
import pandas as pd

# Function to create the heatmap
def create_cwe_platform_heatmap(df_expanded, selected_platform=None, selected_cwe=None):
    # Filter data for heatmap
    df_filtered = df_expanded.copy()
    if selected_platform:
        df_filtered = df_filtered[df_filtered['platforms'].isin(selected_platform)]
    if selected_cwe:
        df_filtered = df_filtered[df_filtered['cwe-id'].isin(selected_cwe)]

    # Create the pivot table for heatmap
    pivot_table = df_filtered.pivot_table(index='platforms', columns='cwe-id', aggfunc='size', fill_value=0)

    # Create the heatmap
    heatmap = go.Figure(go.Heatmap(
        z=pivot_table.values,
        x=pivot_table.columns,
        y=pivot_table.index,
        colorscale='sunset'
    ))
    heatmap.update_layout(title='Heatmap of CWE Occurrences Across Platforms')

    return heatmap

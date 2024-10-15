import plotly.graph_objects as go
import pandas as pd

# Function to create an interactive heatmap for CVE and Technique relationships
def create_cve_technique_heatmap(df,selected_technique=None):
    # Extract relevant columns for the heatmap (CVE ID and Technique)
    df_heatmap = df[['cve', 'technique-id']].dropna()

    # Remove rows where 'cve' or 'technique-id' contains 'UNKNOWN'
    df_heatmap = df_heatmap[df_heatmap['cve'] != 'UNKNOWN']

    # Apply technique filtering if 'selected_technique' is provided
    if selected_technique:
        df_heatmap = df_heatmap[df_heatmap['technique-id'].isin(selected_technique)]

    # Create a crosstab (matrix) to show the number of times each CVE is associated with each Technique
    cve_technique_matrix = pd.crosstab(df_heatmap['cve'], df_heatmap['technique-id'])



    # Create the interactive heatmap with Plotly
    heatmap_fig = go.Figure(
        data=go.Heatmap(
            z=cve_technique_matrix.values,
            x=cve_technique_matrix.columns,
            y=cve_technique_matrix.index,
            colorscale='Blues'
        )
    )

    # Add titles and labels
    heatmap_fig.update_layout(
        title='Interactive Heatmap of CVE and Technique Relationships',
        xaxis_title='Technique ID',
        yaxis_title='CVE ID',
        xaxis=dict(tickangle=90),  # Rotate x-axis labels for readability
    )

    return heatmap_fig

import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import pandas as pd
import plotly.express as px


# Sample heatmap function
def create_heatmap_cve_technique(df):
    """
    This function generates a heatmap for CVE and Technique relationships.

    Parameters:
    df (DataFrame): The input DataFrame containing CVE and Technique data.

    Returns:
    fig: The Plotly heatmap figure object.
    """
    df_heatmap = df[['cve', 'technique-id']].dropna()
    df_heatmap = df_heatmap[df_heatmap['cve'] != 'UNKNOWN']
    cve_technique_matrix = pd.crosstab(df_heatmap['cve'], df_heatmap['technique-id'])

    if cve_technique_matrix.empty:
        raise ValueError("No data available for heatmap generation.")

    fig = px.imshow(cve_technique_matrix,
                    labels=dict(x="Technique ID", y="CVE ID", color="Count"),
                    color_continuous_scale='Blues',
                    title='Heatmap of CVE and Technique Relationships')
    fig.update_layout(
        width=1000,  # Set desired width in pixels (adjust as needed)
        height=610,  # Set desired height in pixels (adjust as needed)
        title_x=0.5,  # Center the title
        margin=dict(l=40, r=40, t=40, b=40)  # Adjust margins to fit better
    )


    return fig

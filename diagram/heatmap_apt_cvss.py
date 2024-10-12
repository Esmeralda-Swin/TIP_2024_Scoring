import pandas as pd
import plotly.express as px


def create_heatmap_apt_cvss(df):
    """
    Create a heatmap for APT groups vs CVSS score categories.

    Parameters:
    df (DataFrame): The input DataFrame containing APT and CVSS data.

    Returns:
    fig: The Plotly heatmap figure object.
    """
    # Extract relevant columns: APT group (Source name) and CVSS-V3 (Severity score)
    df_heatmap = df[['apt', 'cvss-base-score']].dropna()

    # Categorize CVSS scores into custom bins for visualization
    df_heatmap['cve'] = pd.cut(df_heatmap['cvss-base-score'],
                                         bins=[0, 3.9, 6.9, 8.9, 10],
                                         labels=['Low', 'Medium', 'High', 'Critical'])

    # Create a crosstab to count the number of CVEs per APT group and CVSS Category
    apt_cvss_matrix = pd.crosstab(df_heatmap['apt'], df_heatmap['cve'])

    # Create the heatmap figure
    fig = px.imshow(apt_cvss_matrix,
                    labels=dict(x="cve", y="APT Group (Source Name)", color="Count"),
                    color_continuous_scale='YlGnBu',
                    title='Heatmap of APT Groups vs CVSS Categories')

    return fig

import pandas as pd
import plotly.express as px


def create_bubble_chart(df):
    """
    Create a bubble chart of CVEs by APT group and severity.

    Parameters:
    df (DataFrame): The input DataFrame containing APT and CVSS data.

    Returns:
    fig: The Plotly bubble chart figure object.
    """
    # Extract relevant columns: APT group (Source name) and CVSS-V3 (Severity score)
    df_bubble = df[['apt', 'cvss-base-score']].dropna()

    # Create a count for the number of CVEs per APT group and average CVSS for bubble size
    df_bubble_chart = df_bubble.groupby('apt').agg(
        CVE_Count=('cvss-base-score', 'count'),
        Avg_CVSS=('cvss-base-score', 'mean')
    ).reset_index()

    # Create a bubble chart using Plotly Express
    fig = px.scatter(
        df_bubble_chart,
        x='apt',
        y='CVE_Count',
        size='Avg_CVSS',
        color='Avg_CVSS',
        title='Bubble Chart of CVEs by APT Group and Severity',
        labels={'APT': 'APT Group', 'CVE_Count': 'Number of CVEs', 'Avg_CVSS': 'Average CVSS Score'},
        color_continuous_scale='Blues',
        size_max=15
    )

    return fig

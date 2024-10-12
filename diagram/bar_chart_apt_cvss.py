import pandas as pd
import plotly.express as px

def create_bar_chart_apt_cvss(df):
    """
    Create a bar chart of Average CVSS Score by APT Group.

    Parameters:
    df (DataFrame): The input DataFrame containing APT and CVSS data.

    Returns:
    fig: The Plotly bar chart figure object.
    """
    # Extract relevant columns: APT group (Source name) and CVSS-V3 (Severity score)
    df_bar = df[['apt', 'cvss-base-score']].dropna()

    # Group by APT group and calculate the average CVSS score for each group
    df_bar_chart = df_bar.groupby('apt').agg(Avg_CVSS=('cvss-base-score', 'mean')).reset_index()

    # Create the bar chart using Plotly Express
    fig = px.bar(
        df_bar_chart,
        x='apt',
        y='Avg_CVSS',
        title='Average CVSS Score by APT Group',
        labels={'APT': 'APT Group (Source Name)', 'Avg_CVSS': 'Average CVSS Score'},
        color='Avg_CVSS',
        color_continuous_scale='Blues'
    )

    return fig

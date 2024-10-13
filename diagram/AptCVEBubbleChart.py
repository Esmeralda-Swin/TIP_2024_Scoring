import pandas as pd
import plotly.express as px

def create_bubble_chart_apt_cvss(df, selected_apts=None):

    # Extract relevant columns: APT group and CVSS base score
    df_bubble = df[['apt', 'cvss-base-score']].dropna()

    # Apply APT filtering if selected_apts is provided
    if selected_apts:
        df_bubble = df_bubble[df_bubble['apt'].isin(selected_apts)]

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

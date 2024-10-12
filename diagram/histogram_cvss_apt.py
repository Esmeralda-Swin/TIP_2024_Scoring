import pandas as pd
import plotly.express as px


def create_histogram_cvss(df):
    """
    Create a histogram of CVSS scores across all APT groups.

    Parameters:
    df (DataFrame): The input DataFrame containing APT and CVSS data.

    Returns:
    fig: The Plotly histogram figure object.
    """
    # Extract relevant columns: APT group (Source name) and CVSS-V3 (Severity score)
    df_histogram = df[['apt', 'cvss-base-score']].dropna()

    # Create the histogram using Plotly Express
    fig = px.histogram(
        df_histogram,
        x='cvss-base-score',
        nbins=10,
        title='Histogram of CVSS Scores Across All APT Groups',
        labels={'CVSS Score': 'CVSS Score (V3)'},
        color_discrete_sequence=['blue']
    )

    # Add kernel density estimate (KDE)
    fig.add_trace(px.density_contour(df_histogram, x='cvss-base-score').data[0])

    return fig

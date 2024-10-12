import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import pandas as pd
import plotly.graph_objs as go
import seaborn as sns


# Sample pie chart function
def create_pie_chart(data):
    """
    This function generates a pie chart for the top APT Groups by number of techniques used.

    Parameters:
    data (DataFrame): The input DataFrame containing APT Group and Technique Count.

    Returns:
    fig: The Plotly figure object for the pie chart.
    """
    fig = go.Figure(data=[go.Pie(
        labels=data['apt'],
        values=data['Technique Count'],
        hoverinfo='label+percent',
        textinfo='value',
        marker=dict(colors=sns.color_palette("coolwarm", n_colors=10))
    )])

    fig.update_layout(
        title='Top 10 APT Groups by Number of Techniques Used',
    )

    return fig

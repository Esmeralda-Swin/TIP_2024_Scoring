import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import pandas as pd
import plotly.graph_objs as go


# Sample techniques and tactics chart function
def create_techniques_tactics_chart(data):
    """
    This function generates a stacked bar chart for APT Groups with distinct techniques and tactics.

    Parameters:
    data (DataFrame): The input DataFrame containing APT Group, Distinct Technique Count, and Distinct Tactic Count.

    Returns:
    fig: The Plotly figure object for the stacked bar chart.
    """
    fig = go.Figure()

    # Add the bar for distinct techniques
    fig.add_trace(go.Bar(
        x=data['apt'],
        y=data['Distinct Technique Count'],
        name='Distinct Techniques',
        marker_color='blue'
    ))

    # Add the bar for distinct tactics stacked on top
    fig.add_trace(go.Bar(
        x=data['apt'],
        y=data['Distinct Tactic Count'],
        name='Distinct Tactics',
        marker_color='green'
    ))

    # Customize the layout of the stacked bar chart
    fig.update_layout(
        title='APT Groups with the Most Diverse Set of Techniques and Tactics',
        xaxis_title='APT Group',
        yaxis_title='Count of Distinct Techniques and Tactics',
        barmode='stack',
        xaxis_tickangle=-90
    )

    return fig

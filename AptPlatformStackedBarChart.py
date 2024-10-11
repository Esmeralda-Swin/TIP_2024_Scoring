import plotly.express as px
import pandas as pd

# Function to create the stacked bar chart
def create_stacked_bar_chart(data):
    fig = px.bar(
        data,
        x='apt',
        y='count',
        color='platform',
        title='Platforms Matched with APTs',
        labels={'count': 'Number of Occurrences', 'apt': 'APT Groups'},
        barmode='stack'
    )
    return fig

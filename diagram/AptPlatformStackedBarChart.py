import plotly.express as px
import pandas as pd

# Function to create the stacked bar chart
def create_apt_platform_stacked_bar_chart(data):
    fig = px.bar(
        data,
        x='apt',
        y='count',
        color='platforms',
        title='Platforms Matched with APTs',
        labels={'count': 'Number of Occurrences', 'apt': 'APT Groups'},
        barmode='stack'
    )
    return fig

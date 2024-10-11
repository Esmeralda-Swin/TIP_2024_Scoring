import dash
from dash import dcc, html
import plotly.express as px
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.impute import SimpleImputer
import numpy as np

# Path to the Excel file and sheet name
excel = 'VisualAmended_v2.xlsx'
data_sheet = 'CleanedDataset'

# Load the dataset
df = pd.read_excel(excel, sheet_name=data_sheet)

# Grouping by 'platforms' to find the most vulnerable environments
platform_distribution = df.groupby('platforms').size().reset_index(name='count')

# Selecting the top 5 most vulnerable environments by their count
top_platforms = platform_distribution.nlargest(5, 'count')

# Filter the dataset to include only the top 5 environments
top_platforms_data = df[df['platforms'].isin(top_platforms['platforms'])]

# Grouping by 'APT ' and 'platforms' to find APTs targeting the top 5 vulnerable environments
apt_platform_match = top_platforms_data.groupby(['APT', 'platforms']).size().reset_index(name='count')

# Function to create the stacked bar chart using Plotly Express
def create_stacked_bar_chart(data):
    stacked_bar_data = data.pivot_table(index='APT', columns='platforms', values='count', fill_value=0)
    # Create a stacked bar chart using Plotly
    fig = px.bar(stacked_bar_data,
                 title="Top 5 Vulnerable Environments Matched with APTs (Interactive Stacked Bar Chart)",
                 labels={'value': 'Count', 'index': 'APT'},
                 barmode='stack')
    return fig

# Initialize the Dash app
app = dash.Dash(__name__)

# Layout of the dashboard
app.layout = html.Div([
    html.H1("APT Platform Dashboard"),

    # Adding the stacked bar chart to the layout
    dcc.Graph(
        id='stacked-bar-chart',
        figure=create_stacked_bar_chart(apt_platform_match)
    ),
])

# Run the Dash app
if __name__ == '__main__':
    app.run_server(debug=True)

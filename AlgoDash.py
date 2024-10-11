import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import pandas as pd

# Import autonomous.py and manual.py
from autonomous import auto_layout, auto_callbacks
from manual import manual_layout, manual_callbacks

# Initialize the Dash app
app = dash.Dash(__name__)
app.config.suppress_callback_exceptions = True  # Suppress callback exceptions if components are conditionally loaded

# Load the dataset in the AlgoDash.py file
excel = 'RawDataset.xlsx'
data_sheet = 'dataset2'
df = pd.read_excel(excel, sheet_name=data_sheet)

# Define the layout of the dashboard
app.layout = html.Div([
    # Title
    html.H1("APT and Vulnerability Dashboard", style={'textAlign': 'center'}),

    # Create tabs
    dcc.Tabs(id="tabs", value='auto-tab', children=[
        dcc.Tab(label='Autonomous', value='auto-tab'),
        dcc.Tab(label='Manual', value='manual-tab'),
    ]),

    # Tab content container
    html.Div(id='tabs-content')
])


# Callback to switch between tabs and render content dynamically
@app.callback(
    Output('tabs-content', 'children'),
    [Input('tabs', 'value')]
)
def render_content(tab):
    if tab == 'auto-tab':
        return auto_layout  # Ensure this is a valid component
    elif tab == 'manual-tab':
        return manual_layout(df)  # Call the function with df


# Register the callbacks from the autonomous module
auto_callbacks(app)

# Register the callbacks from the manual module
manual_callbacks(app)

# Run the app
if __name__ == '__main__':
    app.run_server(debug=True)

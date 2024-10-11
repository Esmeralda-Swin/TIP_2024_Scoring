import dash
from dash import dcc, html
from dash.dependencies import Input, Output

# Import tab contents
from autonomous import autonomous_tab_layout, autonomous_callbacks
from manual import manual_tab_layout, manual_callbacks

# Initialize the Dash app
app = dash.Dash(__name__)

# Define the layout of the dashboard
app.layout = html.Div([

    # Title
    html.H1("APT and Vulnerability Dashboard", style={'textAlign': 'center'}),

    # Create tabs
    dcc.Tabs(id="tabs", value='autonomous-tab', children=[
        dcc.Tab(label='Autonomous', value='autonomous-tab'),
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
    if tab == 'autonomous-tab':
        return autonomous_tab_layout
    elif tab == 'manual-tab':
        return manual_tab_layout


# Register the callbacks from autonomous and manual modules
autonomous_callbacks(app)
manual_callbacks(app)

# Run the app
if __name__ == '__main__':
    app.run_server(debug=True)

import dash
from dash import dcc, html, Output, Input, State
import pandas as pd
from dash.exceptions import PreventUpdate

# Load the dataset
excel = 'RawDataset.xlsx'
data_sheet = 'dataset2'
df = pd.read_excel(excel, sheet_name=data_sheet)

# Preprocess data
df_techniques = df.groupby('apt')['technique-id'].nunique().reset_index()
df_techniques.columns = ['apt', 'Number_of_Techniques_Used']
df_final = pd.merge(df_techniques, df, on='apt')
df_final['Complexity'] = df_final['Number_of_Techniques_Used'] + df_final['platform-count'] + df_final['tactic-score']
df_final['Prevalence'] = (
    df_final['region-weight'] + df_final['cve-count'] + df_final['cvss-base-score'] + df_final['ioc-weight'] +
    df_final['Time'].apply(lambda t: (t ** 2 - 1) / 2)
)
df_final['Threat_Actor_Score'] = df_final['Complexity'] * df_final['Prevalence']
df_avg_scores = df_final.groupby('apt', as_index=False).agg({
    'Number_of_Techniques_Used': 'mean',
    'Complexity': 'mean',
    'Prevalence': 'mean',
    'Threat_Actor_Score': 'mean'
})
df_avg_scores['Threat_Actor_Score_Percentage'] = (
    (df_avg_scores['Threat_Actor_Score'] - df_avg_scores['Threat_Actor_Score'].min() - 1) /
    (df_avg_scores['Threat_Actor_Score'].max() - df_avg_scores['Threat_Actor_Score'].min() + 1)
) * 100

# Initialize the layout for the manual tab
def manual_layout(df):
    return dcc.Tab(label='Manual', children=[
        html.Div([
            html.H3("Analysis Inputs"),
            html.Label("Select APT:"),
            dcc.RadioItems(
                id='apt-selection',
                options=[
                    {'label': 'Existing APT', 'value': 'existing'},
                    {'label': 'New APT', 'value': 'new'}
                ],
                value='existing',  # default value
                labelStyle={'display': 'inline-block'}
            ),
            html.Div(style={'height': '10px'}),  # Spacing

            dcc.Dropdown(
                id='apt-dropdown',
                options=[{'label': apt, 'value': apt} for apt in df['apt'].unique()],
                placeholder="Select APT"
            ),
            html.Div(style={'height': '10px'}),  # Spacing

            html.Label("Enter New APT Name:"),
            dcc.Input(
                id='new-apt-input',
                type='text',
                placeholder='Enter new APT name',
                disabled=True  # Initially disabled
            ),
            html.Div(style={'height': '10px'}),  # Spacing

            html.Label("No of Technique(s):"),
            dcc.Input(
                id='technique-input',
                type='number',
                placeholder='Enter a number',
                min=0,
                step=1
            ),
            html.Div(style={'height': '10px'}),  # Spacing

            html.Label("Select Tactic:"),
            dcc.Dropdown(
                id='tactic-dropdown',
                options=[{'label': tactic, 'value': tactic} for tactic in df['tactic-description'].unique()],
                placeholder="Select Tactic"
            ),
            html.Div(style={'height': '10px'}),  # Spacing

            html.Div([html.Label("Tactic ID:"), html.Div(id='tactic-id', style={'margin-bottom': '10px'})]),
            html.Div(style={'height': '10px'}),  # Spacing

            html.Div([html.Label("Tactic Score:"), html.Div(id='tactic-score', style={'margin-bottom': '10px'})]),
            html.Div(style={'height': '10px'}),  # Spacing

            html.Label("Select Country of Origin:"),
            dcc.Dropdown(
                id='region-dropdown',
                options=[{'label': region, 'value': region} for region in df['region'].unique()] +
                        [{'label': 'Other', 'value': 'Other'}],  # Adding 'Other' option
                placeholder="Select Country"
            ),
            html.Div(style={'height': '10px'}),  # Spacing

            # Custom country input field
            dcc.Input(
                id='custom-country-input',
                type='text',
                placeholder='Enter custom country name',
                style={'display': 'none'}
            ),
            html.Div(style={'height': '10px'}),  # Spacing

            # Region weight input field
            dcc.Input(
                id='region-weight-input',
                type='number',
                placeholder='Enter region weight score',
                min=0,
                step=0.1,
                style={'display': 'none'}
            ),
            html.Div(style={'height': '10px'}),  # Spacing

            html.Div([html.Label("Region Weight Score:"), html.Div(id='region-weight', style={'margin-bottom': '10px'})]),
            html.Div(style={'height': '10px'}),  # Spacing

            html.Label("CVSS Score: "),
            dcc.Input(
                id='cvss-score-input',
                type='number',
                placeholder='Enter CVSS score; between 0 - 10 ',
                min=0,
                max=10,
                step=0.1
            ),
            html.Div(style={'height': '10px'}),  # Spacing

            html.Label("CVE Count:"),
            dcc.Input(
                id='cve-count-input',
                type='number',
                placeholder='Enter CVE count; min 1',
                min=1,
                step=1
            ),
            html.Div(style={'height': '10px'}),  # Spacing

            html.Label("Time (No. of Years):"),
            dcc.Input(
                id='time-input',
                type='number',
                placeholder='Enter no. of years',
                min=0,
                step=1
            ),
            html.Div(style={'height': '10px'}),  # Spacing

            html.Button('Analyze', id='manual-submit-button', n_clicks=0),
            html.Div(style={'height': '10px'}),  # Spacing

            html.Div(id='manual-output-container', style={'margin-top': '20px'})
        ])
    ])

# Register callbacks for the manual tab
def manual_callbacks(app, df):
    @app.callback(
        Output('new-apt-input', 'disabled'),
        Input('apt-selection', 'value')
    )
    def update_new_apt_input(selection):
        return selection != 'new'

    @app.callback(
        Output('custom-country-input', 'style'),
        Output('region-weight-input', 'style'),
        Input('region-dropdown', 'value')
    )
    def toggle_custom_country_input(region):
        if region == 'Other':
            return {'display': 'block'}, {'display': 'block'}
        return {'display': 'none'}, {'display': 'none'}

    @app.callback(
        Output('manual-output-container', 'children'),
        [Input('manual-submit-button', 'n_clicks')],
        [State('apt-selection', 'value'),
         State('apt-dropdown', 'value'),
         State('new-apt-input', 'value'),
         State('technique-input', 'value'),
         State('tactic-dropdown', 'value'),
         State('region-dropdown', 'value'),
         State('custom-country-input', 'value'),
         State('cvss-score-input', 'value'),
         State('cve-count-input', 'value'),
         State('time-input', 'value')]
    )
    def analyze_apt(n_clicks, apt_selection, existing_apt, new_apt, technique_count, tactic, region, custom_country, cvss_score, cve_count, time):
        if n_clicks > 0:
            # Implement your analysis logic here
            return "Analysis complete!"  # Placeholder for output
        raise PreventUpdate

# Initialize the app and add the layout and callbacks
app = dash.Dash(__name__, suppress_callback_exceptions=True)

app.layout = dcc.Tabs([manual_layout(df)])

manual_callbacks(app, df)

if __name__ == '__main__':
    app.run_server(debug=True)

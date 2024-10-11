import dash
from dash import dcc, html
import pandas as pd
import re
from dash.exceptions import PreventUpdate

# Load the dataset
excel = 'RawDataset.xlsx'
data_sheet = 'dataset2'
df = pd.read_excel(excel, sheet_name=data_sheet)

# Calculate the number of techniques used by each APT
df_techniques = df.groupby('apt')['technique-id'].nunique().reset_index()
df_techniques.columns = ['apt', 'Number_of_Techniques_Used']

# Combine to the dataset
df_final = pd.merge(df_techniques, df, on='apt')

# Calculate Complexity
df_final['Complexity'] = df_final['Number_of_Techniques_Used'] + df_final['platform-count'] + df_final['tactic-score']


# Integrate Time
def integrate_time(t): return (t ** 2 - 1) / 2


# Calculate Prevalence using integration of time
df_final['Prevalence'] = (
        df_final['region-weight'] + df_final['cve-count'] + df_final['cvss-base-score'] + df_final['ioc-weight'] +
        df_final['Time'].apply(integrate_time)
)

# Calculate the Final Threat Actor Score
df_final['Threat_Actor_Score'] = df_final['Complexity'] * df_final['Prevalence']

# Calculate the average as there are 3 entries for each threat actor
df_avg_scores = df_final.groupby('apt', as_index=False).agg({
    'Number_of_Techniques_Used': 'mean',
    'Complexity': 'mean',
    'Prevalence': 'mean',
    'Threat_Actor_Score': 'mean'
})

# Rounding the scores to 2 decimal points
df_avg_scores['Complexity'] = df_avg_scores['Complexity'].round(2)
df_avg_scores['Prevalence'] = df_avg_scores['Prevalence'].round(2)
df_avg_scores['Threat_Actor_Score'] = df_avg_scores['Threat_Actor_Score'].round(2)

# Calculate min and max scores to be used for the percentage calculation
min_score = (df_avg_scores['Threat_Actor_Score'].min())-1
max_score = (df_avg_scores['Threat_Actor_Score'].max())+1

# Calculate Threat Actor Score as a percentage
df_avg_scores['Threat_Actor_Score_Percentage'] = ((df_avg_scores['Threat_Actor_Score'] - min_score) / (
            max_score - min_score)) * 100
df_avg_scores['Threat_Actor_Score_Percentage'] = df_avg_scores['Threat_Actor_Score_Percentage'].round(
    2)  # Round to 2 decimals

# Display the final results with only one entry per APT
print(df_avg_scores[['apt', 'Complexity', 'Prevalence', 'Threat_Actor_Score_Percentage']])

# Initialize the Dash app
app = dash.Dash(__name__)

# Define the layout of the dashboard
app.layout = html.Div([

    # Title
    html.H1("APT and Vulnerability Dashboard", style={'textAlign': 'center'}),

    # Create tabs
    dcc.Tabs([
        dcc.Tab(label='Autonomous', children=[
            html.Div([
                html.H3("Autonomous APT Selection"),

                # Dropdown for selecting APT
                html.Label("Select APT:"),
                dcc.Dropdown(
                    id='autonomous-apt-dropdown',
                    options=[{'label': apt, 'value': apt} for apt in df['apt'].unique()],
                    placeholder="Select APT"
                ),
                html.Div(style={'height': '10px'}),  # Spacing

                # Button to submit the selection in the autonomous tab
                html.Button('Submit', id='autonomous-submit-button', n_clicks=0),
                html.Div(style={'height': '10px'}),  # Spacing

                # Placeholder for any results or outputs in the autonomous tab
                html.Div(id='autonomous-output-container', style={'margin-top': '20px'})
            ])
        ]),
        dcc.Tab(label='Manual', children=[
            html.Div([

                # Section title
                html.H3("Analysis Inputs"),

                # Radio items for selecting existing or new APT
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

                # Dropdown for existing APT name
                dcc.Dropdown(
                    id='apt-dropdown',
                    options=[{'label': apt, 'value': apt} for apt in df['apt'].unique()],
                    placeholder="Select APT",
                    disabled=False  # Initially enabled
                ),
                html.Div(style={'height': '10px'}),  # Spacing

                # Input field for new APT name (enabled only when 'New' is selected)
                html.Label("Enter New APT Name:"),
                dcc.Input(
                    id='new-apt-input',
                    type='text',
                    placeholder='Enter new APT name',
                    disabled=True  # Initially disabled
                ),
                html.Div(style={'height': '10px'}),  # Spacing

                # Input field for No. of Techniques
                html.Label("No of Technique(s):"),
                dcc.Input(
                    id='technique-input',
                    type='number',
                    placeholder='Enter a number',
                    min=0,
                    step=1
                ),
                html.Div(style={'height': '10px'}),  # Spacing

                # Dropdown for selecting tactic description
                html.Label("Select Tactic:"),
                dcc.Dropdown(
                    id='tactic-dropdown',
                    options=[{'label': tactic, 'value': tactic} for tactic in df['tactic-description'].unique()],
                    placeholder="Select Tactic"
                ),
                html.Div(style={'height': '10px'}),  # Spacing

                # Display Tactic ID and Tactic Score
                html.Div([
                    html.Label("Tactic ID:"),
                    html.Div(id='tactic-id', style={'margin-bottom': '10px'}),
                ]),
                html.Div(style={'height': '10px'}),  # Spacing

                html.Div([
                    html.Label("Tactic Score:"),
                    html.Div(id='tactic-score', style={'margin-bottom': '10px'})
                ]),
                html.Div(style={'height': '10px'}),  # Spacing

                # Dropdown for selecting country and displaying weight score
                html.Label("Select Country of Origin:"),
                dcc.Dropdown(
                    id='region-dropdown',
                    options=[
                                {'label': region, 'value': region} for region in df['region'].unique()
                            ] + [{'label': 'Other', 'value': 'Other'}],  # Adding 'Other' option
                    placeholder="Select Country"
                ),
                html.Div(style={'height': '10px'}),  # Spacing

                # Input field for custom country name (shown only when 'Other' is selected)
                html.Div(id='custom-country-container', style={'display': 'none'}),
                dcc.Input(
                    id='custom-country-input',
                    type='text',
                    placeholder='Enter custom country name',
                    style={'display': 'none'}
                ),
                html.Div(style={'height': '10px'}),  # Spacing

                # Input field for region weight score (shown only when 'Other' is selected)
                html.Div(id='region-weight-container', style={'display': 'none'}),
                dcc.Input(
                    id='region-weight-input',
                    type='number',
                    placeholder='Enter region weight score',
                    min=0,
                    step=0.1,
                    style={'display': 'none'}
                ),
                html.Div(style={'height': '10px'}),  # Spacing

                # Display Region Weight Score
                html.Div([
                    html.Label("Region Weight Score:"),
                    html.Div(id='region-weight', style={'margin-bottom': '10px'}),
                ]),
                html.Div(style={'height': '10px'}),  # Spacing

                # Input field for CVSS Score (Validation: numbers from 0 to 10)
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

                # Input field for CVE Count (Validation: minimum 1)
                html.Label("CVE Count :"),
                dcc.Input(
                    id='cve-count-input',
                    type='number',
                    placeholder='Enter CVE count; min 1',
                    min=1,
                    step=1
                ),
                html.Div(style={'height': '10px'}),  # Spacing

                # Input field for Time (Validation: only integers)
                html.Label("Time (No. of Years) :"),
                dcc.Input(
                    id='time-input',
                    type='number',
                    placeholder='Enter no. of years',
                    min=0,
                    step=1
                ),
                html.Div(style={'height': '10px'}),  # Spacing

                # Button to analyze the selected APT or add new APT
                html.Button('Analyze', id='manual-submit-button', n_clicks=0),
                html.Div(style={'height': '10px'}),  # Spacing

                # Placeholder for displaying output
                html.Div(id='manual-output-container', style={'margin-top': '20px'})
            ])
        ])
    ])
])


# Callback for autonomous submit button
@app.callback(
    dash.dependencies.Output('autonomous-output-container', 'children'),
    [dash.dependencies.Input('autonomous-submit-button', 'n_clicks')],
    [dash.dependencies.State('autonomous-apt-dropdown', 'value')]
)
def autonomous_submit(n_clicks, selected_apt):
    if n_clicks > 0:
        if selected_apt is None:
            return "Error: Please select an APT."

        # Filter results based on selected APT
        filtered_results = df_avg_scores[df_avg_scores['apt'] == selected_apt]

        if filtered_results.empty:
            return "No results found for the selected APT."

        # Extracting the necessary information for display
        complexity = filtered_results['Complexity'].values[0]
        prevalence = filtered_results['Prevalence'].values[0]
        threat_actor_score_percentage = filtered_results['Threat_Actor_Score_Percentage'].values[0]

        return html.Div([
            html.Div(f"You have selected the APT: {selected_apt}."),
            html.Div(f"Complexity: {complexity}"),
            html.Div(f"Prevalence: {prevalence}"),
            html.Div(f"Threat Actor Score Percentage: {threat_actor_score_percentage}%")
        ])
    raise PreventUpdate


# Callbacks for manual tab inputs and actions can be added here as needed...

# Run the app
if __name__ == '__main__':
    app.run_server(debug=True)

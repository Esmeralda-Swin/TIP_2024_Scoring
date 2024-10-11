import dash
from dash import dcc, html, Output, Input, State
import pandas as pd
import geopandas as gpd  # Import GeoPandas for geographical data
import re  # For regex validation
from dash.exceptions import PreventUpdate

# Load country names from GeoDataFrame
geojson_path = r'C:\Users\esmer\ne_110m_admin_0_countries\ne_110m_admin_0_countries.shp'  # Update this path
world = gpd.read_file(geojson_path)

# Extract the list of country names and sort in ascending order
countries = sorted(world['NAME_EN'].unique())  # Get unique country names and sort them

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
df_avg_scores['Threat_Actor_Score_Percentage'] = df_avg_scores['Threat_Actor_Score_Percentage'].round(2)  # Round to 2 decimals

# Display the final results with only one entry per APT
print(df_avg_scores[['apt', 'Complexity', 'Prevalence', 'Threat_Actor_Score_Percentage']])

# Initialize the layout for the manual tab
def manual_layout(df):
    return dcc.Tab(label='Manual', children=[
        html.Div([
            html.H3("Analysis Inputs"),
            html.Label("Select a Threat Actor:"),
            dcc.RadioItems(
                id='apt-selection',
                options=[
                    {'label': 'Existing', 'value': 'existing'},
                    {'label': 'New', 'value': 'new'}
                ],
                value='existing',  # default value
                labelStyle={'display': 'inline-block'}
            ),
            html.Div(style={'height': '10px'}),  # Spacing

            dcc.Dropdown(
                id='apt-dropdown',
                options=[{'label': apt, 'value': apt} for apt in df['apt'].unique()],
                placeholder="Select a Threat Actor",
                disabled=False  # Enabled by default
            ),
            html.Div(style={'height': '10px'}),  # Spacing

            html.Label("New Threat Actor:"),
            dcc.Input(
                id='new-apt',
                type='text',
                placeholder='Enter a threat actor',
                disabled=True  # Initially disabled
            ),
            html.Div(style={'height': '10px'}),  # Spacing

            html.Label("No of Technique(s):"),
            dcc.Input(
                id='new-tech',
                type='number',
                placeholder='Enter a number',
                min=0,
                step=1
            ),
            html.Div(style={'height': '10px'}),  # Spacing

            html.Label("Select a Tactic:"),
            dcc.Dropdown(
                id='tactic-dropdown',
                options=[
                    {'label': f"{tactic_id} - {tactic_description}", 'value': tactic_id}
                    for tactic_id, tactic_description in pd.DataFrame(
                        {'tactic-ID': df['tactic-ID'], 'tactic-description': df['tactic-description']}
                    ).drop_duplicates().values
                ],
                placeholder="Select Tactic"
            ),
            html.Div(style={'height': '10px'}),  # Spacing

            html.Div([html.Div(id='tactic-score', style={'margin-bottom': '10px'})]),

            html.Label("Select Country of Origin:"),
            dcc.Dropdown(
                id='region-dropdown',
                options=[{'label': country, 'value': country} for country in countries],
                placeholder="Select Country"
            ),
            html.Div(style={'height': '10px'}),  # Spacing

            # Display for existing region weight
            html.Label("Region Weight Score:"),
            html.Div(id='region-weight-display', style={'margin-bottom': '10px'}),  # Display for existing region weight
            dcc.Dropdown(
                id='region-weight-dropdown',
                options=[{'label': str(i), 'value': i} for i in range(1, 11)],  # Options from 1 to 10
                placeholder="Select Region Weight",
                style={'display': 'none'}  # Initially hidden
            ),
            html.Div(style={'height': '10px'}),  # Spacing

            html.Label("CVSS Score: "),
            dcc.Input(
                id='new-cvss',
                type='number',
                placeholder='Enter CVSS score; between 0 - 10 ',
                min=0,
                max=10,
                step=0.1
            ),
            html.Div(style={'height': '10px'}),  # Spacing

            html.Label("CVE Count:"),
            dcc.Input(
                id='new-cve-count',
                type='number',
                placeholder='Enter CVE count; min 1',
                min=1,
                step=1
            ),
            html.Div(style={'height': '10px'}),  # Spacing

            html.Label("Time (No. of Years):"),
            dcc.Input(
                id='new-time',
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
    # Callback for APT selection
    @app.callback(
        Output('apt-dropdown', 'disabled'),
        Output('new-apt', 'disabled'),
        Input('apt-selection', 'value')
    )
    def update_apt_inputs(selection):
        if selection == 'existing':
            return False, True  # Enable dropdown, disable new APT input
        else:
            return True, False  # Disable dropdown, enable new APT input

    # Combined callback for APT name validation and analysis
    @app.callback(
        Output('manual-output-container', 'children'),
        Input('manual-submit-button', 'n_clicks'),
        Input('new-apt', 'value'),
        State('apt-selection', 'value'),
        State('apt-dropdown', 'value'),
        State('new-tech', 'value'),
        State('tactic-dropdown', 'value'),
        State('region-dropdown', 'value'),
        State('new-cvss', 'value'),
        State('new-cve-count', 'value'),
        State('new-time', 'value')
    )
    def handle_apt_analysis(n_clicks, apt_name, apt_selection, existing_apt, technique_count, tactic, region,
                            cvss_score, cve_count, time):
        if n_clicks > 0:
            # Validate APT name
            if apt_selection == 'new' and apt_name and not apt_name.isalnum():
                return "APT name must be alphanumeric!", apt_name  # Return validation message

            # Implement your analysis logic here
            return "Analysis completed!", apt_name

        raise PreventUpdate

    # Callback for region selection
    @app.callback(
        Output('region-weight-display', 'children'),
        Output('region-weight-dropdown', 'style'),
        Input('region-dropdown', 'value')
    )
    def update_region_weight(selected_region):
        if selected_region:
            # Find the region weight from the DataFrame
            region_weight_row = df[df['region'] == selected_region]
            if not region_weight_row.empty:
                region_weight = region_weight_row.iloc[0]['region-weight']  # Change to the actual column name
                return f"Existing Region Weight: {region_weight}", {'display': 'none'}  # Hide dropdown
            else:
                return "No existing weight. Please select from the dropdown:", {'display': 'block'}  # Show dropdown
        return "", {'display': 'none'}  # Hide everything if no region selected


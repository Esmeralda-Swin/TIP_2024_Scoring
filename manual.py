from dash import dcc, html, Output, Input, State, Dash
import pandas as pd
import geopandas as gpd  # Import GeoPandas for geographical data
import re  # For regex validation
from dash.exceptions import PreventUpdate

# Initialize the Dash app
app = Dash(__name__)

# Load country names from GeoDataFrame
geojson_path = r'C:\Users\esmer\ne_110m_admin_0_countries\ne_110m_admin_0_countries.shp'  # Update this path
world = gpd.read_file(geojson_path)

# Extract the list of country names and sort in ascending order
countries = (world['NAME_EN'].unique())  # Get unique country names and sort them
countries = [country.strip() for country in countries]  # Trim spaces from country names
# Replace "People's Republic of China" with "China"
countries = ['China' if country == "People's Republic of China" else country for country in countries]
countries = sorted(countries)

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
def integrate_time(t):
    return (t ** 2 - 1) / 2


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
min_score = (df_avg_scores['Threat_Actor_Score'].min()) - 1
max_score = (df_avg_scores['Threat_Actor_Score'].max()) + 1

# Calculate Threat Actor Score as a percentage
df_avg_scores['Threat_Actor_Score_Percentage'] = ((df_avg_scores['Threat_Actor_Score'] - min_score) / (
        max_score - min_score)) * 100
df_avg_scores['Threat_Actor_Score_Percentage'] = df_avg_scores['Threat_Actor_Score_Percentage'].round(
    2)  # Round to 2 decimals


# Initialize the layout for the manual tab
def manual_layout(df):
    # Sort the tactic dropdown by tactic-description in alphabetical order
    tactic_options = pd.DataFrame(
        {'tactic-ID': df['tactic-ID'], 'tactic-description': df['tactic-description']}
    ).drop_duplicates().sort_values(by='tactic-description').values

    return dcc.Tab(label='Manual', children=[
        html.Div([
            html.H3("Configure Individual Algorithm Parameters"),
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
                options=[{'label': f"{tactic_id} - {tactic_description}", 'value': tactic_id}
                         for tactic_id, tactic_description in tactic_options],
                placeholder="Select Tactic"
            ),
            html.Div(style={'height': '10px'}),  # Spacing

            # Display tactic weight dynamically
            html.Div(id='tactic-score', style={'margin-bottom': '10px'}),

            html.Label("Select Origin Region:"),
            dcc.Dropdown(
                id='region-dropdown',
                options=[{'label': country, 'value': country} for country in countries],
                placeholder="Select Region"
            ),
            html.Div(style={'height': '10px'}),  # Spacing

            # Display for existing region weight
            html.Label(""),
            html.Div(id='region-weight-display', style={'margin-bottom': '10px'}),
            html.Div(style={'height': '10px'}),  # Spacing

            # Input field for new region weight
            html.Label("Enter New Region Weight (0 - 10) :"),
            dcc.Input(
                id='new-region-weight',
                type='number',
                placeholder='Enter region weight',
                min=0,
                max=10,
                step=1,
                disabled=True  # Initially disabled
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
def manual_callbacks(app):
    # Callback for APT selection
    @app.callback(
        [Output('apt-dropdown', 'disabled'),
         Output('new-apt', 'disabled')],
        Input('apt-selection', 'value')
    )
    def update_apt_inputs(selection):
        if selection == 'existing':
            return False, True  # Enable dropdown, disable new APT input
        else:
            return True, False  # Disable dropdown, enable new APT input

    # Callback to display the region weight score and enable new region weight input
    @app.callback(
        [Output('region-weight-display', 'children'),
         Output('new-region-weight', 'disabled')],
        Input('region-dropdown', 'value')
    )
    def display_region_weight(selected_region):
        if selected_region:
            region_weight = df_final.loc[df_final['region'] == selected_region, 'region-weight']
            if not region_weight.empty:
                return f"Region Weight: {region_weight.iloc[0]}", True  # Disable new input
            else:
                return "No region weight available, please enter a region weight.", False  # Enable new input
        return "Select a region.", True  # No selection made; keep new input disabled

    # Callback to display the tactic score based on selection
    @app.callback(
        Output('tactic-score', 'children'),
        Input('tactic-dropdown', 'value')
    )
    def update_tactic_score(selected_tactic):
        if selected_tactic:
            # Replace with your logic to get the tactic score
            tactic_score = df_final.loc[df_final['tactic-ID'] == selected_tactic, 'tactic-score']
            return f"Tactic Weight: {tactic_score.mean():.2f}" if not tactic_score.empty else "Tactic Weight not available."
        return "Select a tactic."

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
        State('new-region-weight', 'value'),  # Get new region weight value
        State('new-cvss', 'value'),
        State('new-cve-count', 'value'),
        State('new-time', 'value')
    )
    def handle_apt_analysis(n_clicks, apt_name, apt_selection, existing_apt, technique_count,
                            tactic, region_weight, new_region_weight, cvss_score, cve_count, time):
        if n_clicks > 0:
            # Validate APT name if adding new
            if apt_selection == 'new':
                if not apt_name or apt_name.strip() == '':
                    return "Please provide a valid Threat Actor name."
                if re.search(r'\s', apt_name.strip()):  # Check for spaces
                    return "Please provide a name without spaces."

            # Create the new data entry
            new_row = {
                'apt': apt_name if apt_selection == 'new' else existing_apt,
                'technique-id': technique_count,
                'tactic-ID': tactic,
                'region-weight': new_region_weight if new_region_weight is not None else region_weight,
                # Use new region weight
                'cvss-base-score': cvss_score,
                'cve-count': cve_count,
                'Time': time
            }

            # Convert the new row to a DataFrame
            new_row_df = pd.DataFrame([new_row])  # Create a DataFrame for the new row

            # Concatenate the new row to df_final
            global df_final  # Declare df_final as global to modify it
            df_final = pd.concat([df_final, new_row_df], ignore_index=True)  # Append the new row

            return f"Analysis complete for {apt_name if apt_selection == 'new' else existing_apt}."

        raise PreventUpdate  # Prevent updates if no button clicks



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
excel = 'VisualAmended_v9.xlsx'
data_sheet = 'CleanedDataset'
df = pd.read_excel(excel, sheet_name=data_sheet)

# Calculate the number of techniques used by each APT
df_techniques = df.groupby('apt')['technique-id'].nunique().reset_index()
df_techniques.columns = ['apt', 'Number_of_Techniques_Used']

# Combine to the dataset
df_final = pd.merge(df_techniques, df, on='apt')

# Calculate Complexity
df_final['Complexity'] = df_final['Number_of_Techniques_Used'] + df_final['platform-count'] + df_final['tactic-weight']

# Integrate Time
def integrate_time(t):
    return (t ** 2 - 1) / 2

# Calculate Prevalence using integration of time
df_final['Prevalence'] = (
        df_final['region-weight'] + df_final['impact-score'] + df_final['cvss-base-score'] + df_final['ioc-weight'] +
        df_final['time'].apply(integrate_time)
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

# Define a function to categorize the Threat Actor Score Percentage
def categorize_score(score):
    if 0<=score<= 19.99:
        return 'Very Low'
    elif 20<=score<= 39.99:
        return 'Low'
    elif 40<=score<= 59.99:
        return 'Moderate'
    elif 60<=score<= 79.99:
        return 'Critical'
    else:
        return 'Highly Critical'

# Initialize the layout for the manual tab
def manual_layout(df):
    # Sort the tactic dropdown by tactics in alphabetical order
    tactic_options = pd.DataFrame(
        {'tactic-id': df['tactic-id'], 'tactics': df['tactics']}
    ).drop_duplicates().sort_values(by='tactics').values

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

            # New APT input field label and input (hidden by default)
            html.Div(id='new-apt-label', children='New Threat Actor:', style={'display': 'none'}),
            dcc.Input(
                id='new-apt',
                placeholder='Enter new APT...',
                style={'display': 'none'}
            ),
            html.Div(style={'height': '10px'}),  # Spacing

            html.Label(""),
            html.Div(id='manual-output-techniques', style={'margin-bottom': '10px'}),

            html.Label("No of Technique(s):"),
            dcc.Input(
                id='new-tech',
                type='number',
                placeholder='Enter a number',
                min=0,
                step=1
            ),
            html.Div(style={'height': '10px'}),  # Spacing

            html.Label(""),
            dcc.Dropdown(
                id='tactic-dropdown',
                options=[{'label': f"{tactic_id} - {tactic_description}", 'value': tactic_id}
                         for tactic_id, tactic_description in tactic_options],
                placeholder="Select Tactic"
            ),
            html.Div(style={'height': '10px'}),  # Spacing

            # Display tactic weight dynamically
            html.Label("Tactic Weight:  "),
            html.Div(id='tactic-weight-display', style={'margin-bottom': '10px'}),

            html.Label("Select an Origin Region: "),
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
                style={'display': 'none'}
            ),
            html.Div(style={'height': '10px'}),  # Spacing

            html.Label("CVSS Score (0 - 10)"),
            dcc.Input(
                id='new-cvss',
                type='number',
                placeholder='Enter score',
                min=0,
                max=10,
                step=0.1
            ),
            html.Div(style={'height': '10px'}),  # Spacing

            html.Label("Platform count (0 - 10): "),
            dcc.Input(
                id='new-platform',
                type='number',
                placeholder='Enter count',
                min=0,
                max=10,
                step=1
            ),
            html.Div(style={'height': '10px'}),  # Spacing

            html.Label("CVE Count (min=1) :"),
            dcc.Input(
                id='new-impact-score',
                type='number',
                placeholder='Enter CVE count; min 1',
                min=1,
                step=1
            ),
            html.Div(style={'height': '10px'}),  # Spacing

            html.Label("IoC Weight (min=1) :"),
            dcc.Input(
                id='new-ioc-weight',
                type='number',
                placeholder='Enter IoC weight (0 - 10) : ',
                min=1,
                max=10,
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
    # Callback for apt
    @app.callback(
        [Output('apt-dropdown', 'style'),
         Output('new-apt-label', 'style'),
         Output('new-apt', 'style')],
        Input('apt-selection', 'value')
    )
    def update_apt_inputs(selection):
        if selection == 'existing':
            # Show the dropdown and hide the new APT input field
            return  {'display': 'block'}, {'display': 'none'}, {'display': 'none'}
        else:
            # Hide the dropdown and show the new APT input field and label
            return {'display': 'none'}, {'display': 'block'}, {'display': 'block'}

    # Callback to dynamically display the number of techniques for a selected threat actor
    @app.callback(
        Output('manual-output-techniques', 'children'),
        Input('apt-dropdown', 'value')
    )
    def update_technique_count(selected_apt):
        if selected_apt:
            # Fetch the number of techniques associated with the selected threat actor
            techniques_count = df_final.loc[df_final['apt'] == selected_apt, 'technique-id'].nunique()
            return f"Existing technique count for selected Threat Actor: {techniques_count}"
        return ""

    # Callback to display the region weight score and enable new region weight input
    @app.callback(
        [Output('region-weight-display', 'children'),
         Output('new-region-weight', 'style')],
        Input('region-dropdown', 'value')
    )
    def display_region_weight(selected_region):
        if selected_region:
            region_weight = df_final.loc[df_final['region'] == selected_region, 'region-weight']
            if not region_weight.empty:
                # Return the region weight as an integer and hide the new region weight input
                return f"Region Weight: {int(region_weight.iloc[0])}", {'display': 'none'}  # Convert to integer
            else:
                # No region weight available, show the input for the user to enter a new region weight
                return "No region weight available, please enter a region weight.", {'display': 'block'}
        # If no region is selected, hide the new region weight input
        return "", {'display': 'none'}

    # Callback to display the tactic score based on selection
    @app.callback(
        Output('tactic-weight-display', 'children'),
        Input('tactic-dropdown', 'value')
    )
    def update_tactic_score(selected_tactic):
        if selected_tactic:
            tactic_weight = df_final.loc[df_final['tactic-id'] == selected_tactic, 'tactic-weight']

            # Return the tactic weight directly as an integer, if available
            if not tactic_weight.empty:
                return int(tactic_weight.values[0])  # Return integer value directly
            else:
                return "Tactic Weight not available."
        return ""

    # Callback to analyze and display results
    @app.callback(
        Output('manual-output-container', 'children'),
        Input('manual-submit-button', 'n_clicks'),
        State('apt-selection', 'value'),
        State('apt-dropdown', 'value'),
        State('new-apt', 'value'),
        State('new-tech', 'value'),
        State('tactic-dropdown', 'value'),  # Selected tactic
        State('tactic-weight-display', 'children'),  # Capture tactic weight display
        State('region-dropdown', 'value'),  # Selected region
        State('region-weight-display', 'children'),  # Capture region weight display
        State('new-region-weight', 'value'),  # Capture new region weight input
        State('new-cvss', 'value'),
        State('new-platform', 'value'),
        State('new-impact-score', 'value'),
        State('new-ioc-weight', 'value'),
        State('new-time', 'value')
    )
    def analyze(n_clicks, apt_selection, apt, new_apt, new_tech, selected_tactic, tactic_weight_display, region,
                region_weight_display, new_region_weight, cvss, platform,
                impact_score, ioc_weight, time):
        if n_clicks > 0:
            # Create the output string with descriptions
            output = []
            if apt_selection == 'existing':
                output.append(f"Selected Threat Actor: {apt}")
            else:
                output.append(f"New Threat Actor: {new_apt}")

            output.append(f"Number of Techniques: {new_tech}")

            # Use the tactic weight that has already been calculated
            if tactic_weight_display:
                output.append(f"Selected Tactic Weight: {tactic_weight_display}")
            else:
                output.append("Weight not available")

            output.append(f"Selected Origin Region: {region}")

            # Check for existing region weight
            if "No region weight available" not in region_weight_display:
                # Extracting integer value from the display text
                region_weight = region_weight_display.split(': ')[
                    1]  # This will give you the string representation of the weight
                output.append(f"Region Weight: {region_weight}")  # Append existing region weight
            else:
                output.append(f"Region Weight: {new_region_weight}")  # Use the new input if available

            output.append(f"CVSS Score: {cvss}")
            output.append(f"Platform Count: {platform}")
            output.append(f"Impact Score (CVE Count): {impact_score}")
            output.append(f"IoC Weight: {ioc_weight}")
            output.append(f"Time (No. of Years): {time}")

            return html.Div([html.P(desc) for desc in output])

        raise PreventUpdate

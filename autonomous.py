from dash import dcc, html
from dash.dependencies import Input, Output, State
import pandas as pd
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

# Auto tab layout
auto_layout = html.Div([
    html.H3("Auto APT Selection"),
    dcc.Dropdown(
        id='auto-apt-dropdown',
        options=[{'label': apt, 'value': apt} for apt in df['apt'].unique()],
        placeholder="Select APT"
    ),
    html.Button('Submit', id='auto-submit-button', n_clicks=0, style={'margin-top': '20px'}),
    html.Div(id='auto-output-container',)
])

# Callback for auto submit button
def auto_callbacks(app):
    @app.callback(
        Output('auto-output-container', 'children'),
        [Input('auto-submit-button', 'n_clicks')],
        [State('auto-apt-dropdown', 'value')]
    )
    def auto_submit(n_clicks, selected_apt):
        if n_clicks > 0:
            if selected_apt is None:
                return "Error: Please select an APT."

            filtered_results = df_avg_scores[df_avg_scores['apt'] == selected_apt]

            if filtered_results.empty:
                return "No results found for the selected APT."

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

#print loaded data
#print(df.head())  # Check the loaded data

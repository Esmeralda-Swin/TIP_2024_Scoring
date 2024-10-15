from click import style
from dash import dcc, html
from dash.dependencies import Input, Output, State
import pandas as pd
from dash.exceptions import PreventUpdate

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

colors = {
    'background': '#f9f9f9',
    'text': '#333333'
}


# Integrate Time
def integrate_time(t): return (t ** 2 - 1) / 2


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
    if 0 <= score <= 19.99:
        return 'Very Low'
    elif 20 <= score <= 39.99:
        return 'Low'
    elif 40 <= score <= 59.99:
        return 'Moderate'
    elif 60 <= score <= 79.99:
        return 'Critical'
    else:
        return 'Highly Critical'


# Apply the categorization function to the Threat Actor Score Percentage column
df_avg_scores['Threat_Actor_Category'] = df_avg_scores['Threat_Actor_Score_Percentage'].apply(categorize_score)

# Display the final results with only one entry per APT
print(df_avg_scores[['apt', 'Complexity', 'Prevalence', 'Threat_Actor_Score_Percentage', 'Threat_Actor_Category']])

# Auto tab layout
auto_layout = html.Div([
    html.H2("Select a Threat Actor", style={'color': colors['text']}),
    dcc.Dropdown(
        id='auto-apt-dropdown',
        options=[{'label': apt, 'value': apt} for apt in sorted(df['apt'].unique())],  # Sort APTs alphabetically
        placeholder="Select APT"
    ),
    html.Button('Submit', id='auto-submit-button', n_clicks=0, style={'margin-top': '20px'}),
    html.Div(id='auto-output-container', )
], style={
    'height': '100vh',  # Set the height to the full viewport height
    'padding': '10px'  # Add padding if necessary
})


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
            threat_actor_category = filtered_results['Threat_Actor_Category'].values[0]

            return html.Div([
                html.Div(f"You have selected: {selected_apt}."),
                html.Div(f"Complexity: {complexity}"),
                html.Div(f"Prevalence: {prevalence}"),
                html.Div(f"", style={'margin-bottom': '10px'}),
                html.Div(f"Threat Actor Score Percentage: {threat_actor_score_percentage}%"),
                html.Div(f"Threat Actor Category: {threat_actor_category}"),
            ])
        raise PreventUpdate

# print loaded data
# print(df.head())  # Check the loaded data

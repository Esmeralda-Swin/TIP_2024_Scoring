from dash import dcc, html
from dash.dependencies import Input, Output, State
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

# Autonomous tab layout
autonomous_tab_layout = html.Div([
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

# Callback for autonomous submit button
def autonomous_callbacks(app):
    @app.callback(
        Output('autonomous-output-container', 'children'),
        [Input('autonomous-submit-button', 'n_clicks')],
        [State('autonomous-apt-dropdown', 'value')]
    )
    def autonomous_submit(n_clicks, selected_apt):
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

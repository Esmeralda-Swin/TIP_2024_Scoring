from dash import dcc, html, Input, Output, Dash
import pandas as pd
import plotly.express as px

# Define colors
colors = {
    'background': '#f9f9f9',
    'text': '#333333'
}

# Load the dataset
excel = 'novel.xlsx'
data_sheet = 'filtered'
df = pd.read_excel(excel, sheet_name=data_sheet)

# Calculate the number of techniques used by each APT
df_techniques = df.groupby('apt')['technique-id'].nunique().reset_index()
df_techniques.columns = ['apt', 'Number_of_Techniques_Used']

# Combine with the main dataset
df_final = pd.merge(df_techniques, df, on='apt')

# Attacker category
df_category = df.groupby('apt')['attacker-category'].nunique().reset_index()

# Fill NaN values
for column in ['Number_of_Techniques_Used', 'platform-count', 'tactic-weight', 'region-weight',
               'impact-score', 'cvss-base-score', 'time']:
    df_final[column] = df_final[column].fillna(0)


# Define the integrate_time function using the provided formula
def integrate_time(T):
    return (T ** 2 - 1) / 2


# Calculate Complexity
df_final['Complexity'] = (df_final['Number_of_Techniques_Used'] +
                          df_final['platform-count'] +
                          df_final['tactic-weight'])

# Calculate Prevalence using the integrate_time function
df_final['Prevalence'] = (df_final['region-weight'] +
                          df_final['impact-score'] +
                          df_final['cvss-base-score'] +
                          df_final['time'].apply(integrate_time))

# Calculate average scores for the APTs
df_avg_scores = df_final.groupby('apt', as_index=False).agg({
    'Number_of_Techniques_Used': 'mean',
    'Complexity': 'mean',
    'Prevalence': 'mean'
})

# Simulate increasing defense scores for the years 2019 to 2050
initial_defense_score = 1  # Starting defense score
defense_factor = 0.5  # Amount to increase each year
defense_scores = {year: initial_defense_score + defense_factor* (year - 2024) for year in range(2024, 2051)}

# Create a DataFrame for years 2019 to 2050
results = []

for year in range(2019, 2051):
    for index, row in df_avg_scores.iterrows():
        if year in range(2019, 2024):  # For the last 5 years, adjust only Prevalence
            adjusted_prevalence = row['Prevalence']  # Prevalence already incorporates time factor
            probability = (row['Complexity'] * adjusted_prevalence)
        else:  # For 2024 onwards, apply a growth factor to Prevalence
            attack_factor = 1 + 0.05 * (year - 2024)  # Assume growth of 0.05
            current_complexity = row['Complexity'] * attack_factor
            current_prevalence = row['Prevalence'] * attack_factor
            probability = ((current_complexity * current_prevalence * df_final['vulnerability-score'].mean()) /
                           defense_scores[year])  # Use the changing defense score

        # Append results including Probability
        results.append({
            'Year': year,
            'Threat Actor': row['apt'],
            'Complexity': row['Complexity'],
            'Prevalence': row['Prevalence'],
            'Probability': probability,
            'Attacker Category': df.loc[df['apt'] == row['apt'], 'attacker-category'].iloc[0]  # Add attacker category
        })

df_results = pd.DataFrame(results)

# Calculate Probability_Percentage based on the newly calculated Probability
min_probability = df_results['Probability'].min()
max_probability = df_results['Probability'].max()
df_results['Probability_Percentage'] = ((df_results['Probability'] - min_probability) /
                                        (max_probability - min_probability)) * 100

# Define the layout for the novel app
# Define the layout for the novel app
novel_layout = html.Div([
    html.H2("Future Threat Actor Score Modelling", style={'textAlign': 'center', 'color': colors['text']}),
    dcc.Dropdown(
        id='view-dropdown',
        options=[
            {'label': 'By Threat Actor', 'value': 'Threat Actor'},
            {'label': 'By Attacker Category', 'value': 'Attacker Category'}
        ],
        value='Threat Actor',  # Default value
        clearable=False
    ),
    dcc.Graph(id='scatter-plot', config={'displayModeBar': True}),  # Interactive scatter plot
], style={
    'height': '100vh',  # Set the height to the full viewport height
    'padding': '10px'  # Add padding if necessary
})


# # # Define the callbacks for the novel app
# def novel_callbacks(app):
#     @app.callback(
#         Output('scatter-plot', 'figure'),
#         Input('view-dropdown', 'value')  # Input from the dropdown to select the view
#     )
#     def update_scatter_plot(selected_view):
#         # Create the interactive scatter plot
#         if selected_view == 'Threat Actor':
#             color_col = 'Threat Actor'
#         else:
#             color_col = 'Attacker Category'  # Use attacker category for color
#
#         fig = px.scatter(
#             df_results,
#             x='Year',
#             y='Probability_Percentage',
#             color=color_col,
#             hover_name='Threat Actor',  # Always show Threat Actor name in hover
#             hover_data={
#                 'Year': True,
#                 'Probability_Percentage': True,
#                 'Attacker Category': True  # Show Attacker Category if needed
#             },
#             title='Variation of Threat Actor Score vs. Probability of Attack (%) (2019-2050)',
#             labels={'Probability_Percentage': 'Probability of Attack (%)'},  # Updated label
#             trendline='ols'  # Optional: Add a trendline for better visualization
#         )
#
#         return fig

# Define the callbacks for the novel app
def novel_callbacks(app):
    @app.callback(
        Output('scatter-plot', 'figure'),
        Input('view-dropdown', 'value')  # Input from the dropdown to select the view
    )
    def update_scatter_plot(selected_view):
        # Filter the data to only include years from 2025 onwards
        df_filtered = df_results[df_results['Year'] >= 2025]

        # Create the interactive scatter plot
        if selected_view == 'Threat Actor':
            color_col = 'Threat Actor'
        else:
            color_col = 'Attacker Category'  # Use attacker category for color

        fig = px.scatter(
            df_filtered,  # Use the filtered DataFrame
            x='Year',
            y='Probability_Percentage',
            color=color_col,
            hover_name='Threat Actor',  # Always show Threat Actor name in hover
            hover_data={
                'Year': True,
                'Probability_Percentage': True,
                'Attacker Category': True  # Show Attacker Category if needed
            },
            title='Variation of Threat Actor Score vs. Probability of Attack (%) (2024-2050)',
            labels={'Probability_Percentage': 'Probability of Attack (%)'},  # Updated label
            trendline='ols'  # Optional: Add a trendline for better visualization
        )

        return fig


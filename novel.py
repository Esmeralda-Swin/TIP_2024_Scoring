import pandas as pd
import plotly.express as px

# Load the dataset
excel = 'novel.xlsx'
data_sheet = 'filtered'
df = pd.read_excel(excel, sheet_name=data_sheet)

# Calculate the number of techniques used by each APT
df_techniques = df.groupby('apt')['technique-id'].nunique().reset_index()
df_techniques.columns = ['apt', 'Number_of_Techniques_Used']

# Combine with the main dataset
df_final = pd.merge(df_techniques, df, on='apt')

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
growth_rate = 0.05  # Amount to increase each year
defense_scores = {year: initial_defense_score + growth_rate * (year - 2024) for year in range(2024, 2051)}

# Create a DataFrame for years 2019 to 2050
results = []

for year in range(2019, 2051):
    for index, row in df_avg_scores.iterrows():
        if year in range(2019, 2024):  # For the last 5 years, adjust only Prevalence
            adjusted_prevalence = row['Prevalence']  # Prevalence already incorporates time factor

            probability = (row['Complexity'] * adjusted_prevalence)
        else:  # For 2024 onwards, apply a growth factor to Prevalence
            growth_factor = 1 + 0.05 * (year - 2024)  # Assume 5% growth
            current_complexity = row['Complexity'] * growth_factor
            current_prevalence = row['Prevalence'] * growth_factor

            probability = ((current_complexity * current_prevalence * df_final['vulnerability-score'].mean()) /
                           defense_scores[year])  # Use the changing defense score

        # Append results including Probability
        results.append({
            'Year': year,
            'APT': row['apt'],
            'Complexity': row['Complexity'],
            'Prevalence': row['Prevalence'],
            'Probability': probability
        })

df_results = pd.DataFrame(results)

# Calculate Probability_Percentage based on the newly calculated Probability
min_probability = df_results['Probability'].min()
max_probability = df_results['Probability'].max()
df_results['Probability_Percentage'] = ((df_results['Probability'] - min_probability) /
                                        (max_probability - min_probability)) * 100

# Create the interactive scatter plot
fig = px.scatter(df_results,
                 x='Year',
                 y='Probability_Percentage',
                 color='APT',
                 hover_name='APT',
                 hover_data={'Year': True},
                 title='Variation of Threat Actor Score vs. Probability Percentage (2019-2050)',
                 labels={'Probability_Percentage': 'Probability Percentage'},
                 trendline='ols')  # Optional: Add a trendline for better visualization

# Show the plot
fig.show()

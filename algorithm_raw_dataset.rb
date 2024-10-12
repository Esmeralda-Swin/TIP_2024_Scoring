import pandas as pd
df = pd.read_excel('RawDataset.xlsx')

# Calculate the number of techniques used by each APT
df_techniques = df.groupby('apt')['technique-id'].nunique().reset_index()
df_techniques.columns = ['apt', 'Number_of_Techniques_Used']

# Combine to the dataset
df_final = pd.merge(df_techniques, df, on='apt')

# Calculate Complexity
df_final['Complexity'] = df_final['Number_of_Techniques_Used'] + df_final['platform-count'] + df_final['tactic-weight']

# Integrate Time
def integrate_time(T): return ((T**2 - 1)) / 2

# Calculate Prevalence using integration of time
df_final['Prevalence'] = (
    df_final['region-weight'] +df_final['impact-score']  + df_final['cvss-base-score'] + df_final['ioc-weight'] + df_final['time'].apply(integrate_time)
)

# Calculate the Final Threat Actor Score
df_final['Threat_Actor_Score'] = df_final['Complexity'] * df_final['Prevalence']

# Calculate the avareage as there are 3 entries for each threat actor
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

# Calculate min and max scores to be used for the precentage calculation
min_score = (df_avg_scores['Threat_Actor_Score'].min())-1
max_score = (df_avg_scores['Threat_Actor_Score'].max())+1

# Calculate Threat Actor Score as a percentage
df_avg_scores['Threat_Actor_Score_Percentage'] = ((df_avg_scores['Threat_Actor_Score'] - min_score) / (max_score - min_score)) * 100
df_avg_scores['Threat_Actor_Score_Percentage'] = df_avg_scores['Threat_Actor_Score_Percentage'].round(2) # Round to 2 decimals 

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

# Apply the categorization function to the Threat Actor Score Percentage column
df_avg_scores['Threat_Actor_Category'] = df_avg_scores['Threat_Actor_Score_Percentage'].apply(categorize_score)
# print(df_final[['ioc-weight']])
# Display the final results with the new category column
print(df_avg_scores[['apt', 'Complexity', 'Prevalence', 'Threat_Actor_Score_Percentage', 'Threat_Actor_Category']])


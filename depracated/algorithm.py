# apt_analysis.py
import pandas as pd

# Define the path to the Excel file and the data sheet
excel_file = 'VisualAmended_v9.xlsx'
data_sheet = 'CleanedDataset'

def load_and_process_data():
    # Load the dataset
    df = pd.read_excel(excel_file, sheet_name=data_sheet)

    # Calculate the number of techniques used by each APT
    df_techniques = df.groupby('apt')['technique-id'].nunique().reset_index()
    df_techniques.columns = ['apt', 'Number_of_Techniques_Used']

    # Combine to the dataset
    df_final = pd.merge(df_techniques, df, on='apt')

    # Calculate Complexity
    df_final['Complexity'] = (
        df_final['Number_of_Techniques_Used'] +
        df_final['platform-count'] +
        df_final['tactic-weight']
    )

    # Integrate Time
    def integrate_time(t):
        return (t ** 2 - 1) / 2

    # Calculate Prevalence using integration of time
    df_final['Prevalence'] = (
        df_final['region-weight'] +
        df_final['impact-score'] +
        df_final['cvss-base-score'] +
        df_final['ioc-weight'] +
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

    # Calculate min and max scores for percentage calculation
    min_score = df_avg_scores['Threat_Actor_Score'].min() - 1
    max_score = df_avg_scores['Threat_Actor_Score'].max() + 1

    # Calculate Threat Actor Score as a percentage
    df_avg_scores['Threat_Actor_Score_Percentage'] = (
        (df_avg_scores['Threat_Actor_Score'] - min_score) /
        (max_score - min_score) * 100
    ).round(2)

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

    return df_avg_scores[['apt', 'Complexity', 'Prevalence', 'Threat_Actor_Score_Percentage', 'Threat_Actor_Category']]

# Function to get the analysis for a specific APT
def get_apt_analysis(selected_apt):
    df_avg_scores = load_and_process_data()  # Load the full dataset
    # Filter the DataFrame for the selected APT
    apt_data = df_avg_scores[df_avg_scores['apt'] == selected_apt]

    if not apt_data.empty:
        # Return filtered data as a dictionary for easier use
        return apt_data.to_dict(orient='records')
    else:
        return None  # Handle case where no data is found

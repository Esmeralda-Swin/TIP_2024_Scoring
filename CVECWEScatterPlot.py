import plotly.express as px
import pandas as pd

# Load dataset (optional if loaded globally in dashboard.py)
# df_scatter = pd.read_csv('your_dataset.csv')

# Function to create the scatter plot
def create_scatter_plot(df_scatter, selected_cwe=None, selected_cvss=None):
    # Filter data for scatter plot
    df_scatter_filtered = df_scatter.copy()
    if selected_cwe:
        df_scatter_filtered = df_scatter_filtered[df_scatter_filtered['cwe-id'].isin(selected_cwe)]
    if selected_cvss:
        df_scatter_filtered = df_scatter_filtered[df_scatter_filtered['cvss-base-score'].isin(selected_cvss)]

    # Create the scatter plot
    scatter_plot = px.scatter(df_scatter_filtered, x='cwe_num', y='cvss-base-score',
                              hover_data=['cve', 'cwe-id'],
                              title='Scatter Plot of CVEs and Their Associated CWEs',
                              labels={'cwe_num': 'CWE (as Numeric Value)', 'cvss-base-score': 'CVSS Score (V3)'},
                              color='cvss-base-score',
                              color_continuous_scale='Blues')
    return scatter_plot

import plotly.express as px
import pandas as pd

# Load dataset (optional if loaded globally in dashboard.py)
# df_scatter = pd.read_csv('your_dataset.csv')

# Function to create the scatter plot
def create_cve_cwe_scatter_plot(df_scatter, selected_cwe=None, selected_cvss=None):
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
                              labels={'cwe_num': 'CWE (as Numeric Value)', 'cvss-base-score': 'CVSS Score'},
                              color='cvss-base-score',
                              color_continuous_scale='Blues')
    scatter_plot.update_layout(
        coloraxis_colorbar=dict(
            title='CVSS Score',
            title_side='right',
            title_font=dict(size=14),
            lenmode="pixels",  # Set a fixed size for the colorbar
            len=300  # Adjust the length of the colorbar
        )
    )
    return scatter_plot

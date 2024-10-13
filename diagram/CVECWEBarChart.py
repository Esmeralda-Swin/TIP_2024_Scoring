import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import plotly.express as px

# Function to create the bar chart for CVE and CWE
def create_cve_cwe_bar_chart(df):
    # Filter out rows where either 'CWE-ID' is 'Unknown' and 'NVD-CWE-noinfo'
    df_filtered = df[['cve', 'cwe-id']].dropna()
    df_filtered = df_filtered[(df_filtered['cwe-id'] != 'UNKNOWN') & (df_filtered['cwe-id'] != 'NVD-CWE-noinfo')]

    # Group the data by CWE and count the number of CVEs associated with each CWE
    cwe_cve_count = df_filtered.groupby('cwe-id').count().reset_index()
    cwe_cve_count.columns = ['cwe-id', 'CVE Count']

    # Create the bar chart using Plotly Express
    fig = px.bar(
        cwe_cve_count,
        x='cwe-id',
        y='CVE Count',
        title='Bar Chart of Number of CVEs Associated with Each CWE',
        labels={'cwe-id': 'CWE-ID', 'CVE Count': 'Number of CVEs'}
    )

    fig.update_xaxes(tickangle=90)  # Rotate x-axis labels for better readability

    return fig

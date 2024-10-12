import plotly.express as px
import pandas as pd

# Function to create the bar chart for CVE vs CWE
def create_cve_cwe_bar_chart(cwe_cve_count):
    bar_cve_cwe = px.bar(
        cwe_cve_count,
        x='cwe-id',
        y='CVE Count',
        title='Bar Chart of Number of CVEs Associated with Each CWE',
        labels={'cwe-id': 'CWE-ID', 'CVE Count': 'Number of CVEs'}
    )
    bar_cve_cwe.update_xaxes(tickangle=90)  # Rotate x-axis labels for better readability
    return bar_cve_cwe

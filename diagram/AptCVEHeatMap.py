import pandas as pd
import plotly.express as px

def create_heatmap_apt_cvss(df, selected_apts=None):
    # Step 1: Extract relevant columns: APT group and CVSS base score
    df_heatmap = df[['apt', 'cvss-base-score']].dropna()

    # Categorize CVSS scores into custom bins for visualization
    df_heatmap['CVSS Category'] = pd.cut(df_heatmap['cvss-base-score'],
                                         bins=[0, 3.9, 6.9, 8.9, 10],
                                         labels=['Low', 'Medium', 'High', 'Critical'])

    # Apply APT filtering if selected_apts is provided
    if selected_apts:
        df_heatmap = df_heatmap[df_heatmap['apt'].isin(selected_apts)]

    # Create a crosstab to count the number of CVEs per APT group and CVSS Category
    apt_cvss_matrix = pd.crosstab(df_heatmap['CVSS Category'], df_heatmap['apt'])

    # Dynamically adjust the heatmap height based on the number of APTs
    num_apts = len(apt_cvss_matrix.columns)
    height = max(400, num_apts)  # Increase height based on number of APTs

    # Create the heatmap figure with swapped axes
    fig = px.imshow(apt_cvss_matrix,
                    labels=dict(x="APT Group", y="CVSS Severity", color="Count"),
                    color_continuous_scale='YlGnBu',
                    title='Heatmap of APT Groups vs CVSS Categories',
                    height=height)  # Set the height dynamically

    return fig

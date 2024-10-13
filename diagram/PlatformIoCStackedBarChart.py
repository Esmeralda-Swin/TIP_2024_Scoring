import pandas as pd
import plotly.express as px

# Function to create the stacked bar chart
def create_platform_ioc_stacked_bar_chart(df, selected_platforms=None):
    # Ensure 'platforms' column exists and is not NaN
    df['platforms'] = df['platforms'].fillna('')

    # Split platforms by commas and explode into separate rows
    df_expanded = df.assign(platforms=df['platforms'].str.split(',')).explode('platforms')
    df_expanded['platforms'] = df_expanded['platforms'].str.strip()

    # Apply APT filtering if selected
    if selected_platforms:
        df_expanded = df_expanded[df_expanded['platforms'].isin(selected_platforms)]

    # Filter out rows where 'ioc-weight' is 0.0
    df_expanded = df_expanded[df_expanded['ioc-weight'] != 0.0]

    # Identify the top 10 platforms by frequency
    platform_counts = df_expanded['platforms'].value_counts()
    top_10_platforms = platform_counts.head(10).index.tolist()

    # Filter the data to include only the top 10 platforms
    df_top_platforms = df_expanded[df_expanded['platforms'].isin(top_10_platforms)]

    # Create a pivot table with platforms as index and IOC weights as columns
    stacked_data = df_top_platforms.pivot_table(index='platforms', columns='ioc-weight', aggfunc='size', fill_value=0)

    # Reset the pivot table to create x and y data for Plotly
    stacked_data = stacked_data.reset_index()

    # Plot the stacked bar chart using Plotly Express
    fig = px.bar(
        stacked_data.melt(id_vars='platforms', var_name='IOC Weight', value_name='Count'),
        x='platforms',
        y='Count',
        color='IOC Weight',
        title='Top Platforms Matched with IOC Weights',
        labels={'Count': 'Number of Occurrences', 'platforms': 'Platforms'},
        barmode='stack',
        height=600
    )

    return fig

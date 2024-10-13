import plotly.express as px
import pandas as pd

# Function to create the stacked bar chart with filtering
def create_apt_platform_stacked_bar_chart(df, selected_apts=None, selected_platforms=None):
    # Ensure 'platforms' column exists and is not NaN
    df['platforms'] = df['platforms'].fillna('')

    # Split platforms by commas and explode into separate rows
    df_expanded = df.assign(platforms=df['platforms'].str.split(',')).explode('platforms')
    df_expanded['platforms'] = df_expanded['platforms'].str.strip()

    # Identify the top 10 platforms by frequency
    platform_counts = df_expanded['platforms'].value_counts()
    top_10_platforms = platform_counts.head(10).index.tolist()

    # Filter the data to include only the top 10 platforms
    df_top_platforms = df_expanded[df_expanded['platforms'].isin(top_10_platforms)]

    # Apply filtering for selected APTs, if provided
    if selected_apts:
        df_top_platforms = df_top_platforms[df_top_platforms['apt'].isin(selected_apts)]

    # Apply filtering for selected platforms, if provided
    if selected_platforms:
        df_top_platforms = df_top_platforms[df_top_platforms['platforms'].isin(selected_platforms)]

    # Group the data by APT and platform
    apt_platform_counts = df_top_platforms.groupby(['apt', 'platforms']).size().reset_index(name='count')

    # Generate the stacked bar chart
    fig = px.bar(
        apt_platform_counts,
        x='apt',
        y='count',
        color='platforms',
        title='Top 10 Vulnerable Platforms Matched with APTs',
        labels={'count': 'Number of Occurrences', 'apt': 'APT Groups'},
        barmode='stack'
    )
    return fig

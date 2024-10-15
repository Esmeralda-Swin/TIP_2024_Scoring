import dash_bootstrap_components as dbc
from dash import html, dcc
from diagram.Top10AptPieChart import create_pie_chart
from diagram.AptRegionHeatMap import create_region_map

# Define colors (same as in main app for consistency)
colors = {
    'background': '#f9f9f9',
    'text': '#333333'
}


def summary_layout(df, shapefile_path='ne_10m_admin_0_countries/ne_10m_admin_0_countries.shp'):
    # Calculate key metrics
    total_platforms = df['platforms'].nunique()
    total_apts = df['apt'].nunique()

    # Get the Top 10 APT pie chart by calling the function
    top_10_apt_pie_chart = create_pie_chart(df)

    # Remove 'UNKNOWN' values before calculating most vulnerable CVE and CWE
    df_filtered = df[(df['cve'] != 'UNKNOWN') & (df['cwe-id'] != 'UNKNOWN')]
    most_vulnerable_cve = df_filtered['cve'].value_counts().idxmax()
    most_vulnerable_cwe = df_filtered['cwe-id'].value_counts().idxmax()

    # Create the folium map using the create_region_map function
    folium_map = create_region_map(df, shapefile_path=shapefile_path)

    # Convert the folium map to an HTML representation
    map_html = folium_map._repr_html_()

    return dbc.Container([
        html.H2('Summary Overview', style={'textAlign': 'center', 'color': colors['text']}),

        # Key metrics section
        dbc.Row([
            dbc.Col(dbc.Card([
                html.H3(f"{most_vulnerable_cve}", className="card-title"),
                html.P("The Most Vulnerable CVE", className="card-text")
            ], body=True), width=3),
            dbc.Col(dbc.Card([
                html.H3(f"{most_vulnerable_cwe}", className="card-title"),
                html.P("The Most Common CWE", className="card-text")
            ], body=True), width=3),
            dbc.Col(dbc.Card([
                html.H3(f"{total_platforms}", className="card-title"),
                html.P("Affected Platforms", className="card-text")
            ], body=True), width=3),
            dbc.Col(dbc.Card([
                html.H3(f"{total_apts}", className="card-title"),
                html.P("Total Threat Actor Groups", className="card-text")
            ], body=True), width=3),
        ], className="mb-4"),

        # Folium Map (replace Top 5 CVEs by Severity)
        dbc.Row([
            dbc.Col(html.Iframe(srcDoc=map_html, width='100%', height='600'), width=8),
            dbc.Col(dcc.Graph(figure=top_10_apt_pie_chart, style={'height': '600px'}), width=4, )
        ], className="mb-4"),

        # Add more sections or charts as needed
    ], fluid=True, style={
        'height': '100vh',  # Set the height to the full viewport height
        'overflow': 'hidden',  # Disable scrolling
        'padding': '10px'  # Add padding if necessary
    })

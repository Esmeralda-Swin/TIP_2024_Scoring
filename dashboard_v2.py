import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import pandas as pd

# Import the scatter plot, heatmap, bar chart, and stacked bar chart from separate files
from CVECWEScatterPlot import create_scatter_plot
from CWEPlatformHeatmap import create_heatmap
from CVECWEBarChart import create_bar_chart
from AptPlatformStackedBarChart import create_stacked_bar_chart
from AptRegionHeatMap import create_region_map

# Load your dataset
excel = 'VisualAmended_v9.xlsx'
data_sheet = 'CleanedDataset'
df = pd.read_excel(excel, sheet_name=data_sheet)

# Standardize column names and prepare data
df.columns = df.columns.str.lower()
df_scatter = df[['cve', 'cwe-id', 'cvss-base-score']].dropna()
df_scatter['cwe_num'] = pd.factorize(df_scatter['cwe-id'])[0]
df_expanded = df.assign(platform=df['platforms'].str.split(',')).explode('platform')
df_expanded['platform'] = df_expanded['platform'].str.strip()
df_expanded = df_expanded[df_expanded['cwe-id'] != 'UNKNOWN']

# Create data for the bar chart
df_filtered = df[['cve', 'cwe-id']].dropna()
df_filtered = df_filtered[(df_filtered['cwe-id'] != 'UNKNOWN') & (df_filtered['cwe-id'] != 'nvd-cwe-noinfo')]
cwe_cve_count = df_filtered.groupby('cwe-id').count().reset_index()
cwe_cve_count.columns = ['cwe-id', 'CVE Count']

# Group data for the stacked bar chart
apt_platform_counts = df_expanded.groupby(['apt', 'platform']).size().reset_index(name='count')

# Initialize the Dash app
app = dash.Dash(__name__)

# Define the layout of the dashboard
app.layout = html.Div([
    html.H1("Interactive Dashboard for Platforms and CVE/CWE", style={'textAlign': 'center'}),

    # Create buttons for CVE, Platform, and CWE sections
    html.Div([
        html.Button('CVE-Related Visualizations', id='cve-button', n_clicks=0, className='button-83'),
        html.Button('APT-Related Visualizations', id='platform-button', n_clicks=0, className='button-83'),
        html.Button('CWE-Related Visualizations', id='cwe-button', n_clicks=0, className='button-83')
    ], style={'display': 'flex', 'justifyContent': 'center', 'alignItems': 'center', 'height': '50vh'}),

    # Div to display the selected content dynamically
    html.Div(id='section-content', style={'marginTop': 20})
])

# Define the callback to update content based on the clicked button
@app.callback(Output('section-content', 'children'),
              [Input('cve-button', 'n_clicks'),
               Input('platform-button', 'n_clicks'),
               Input('cwe-button', 'n_clicks')])
def render_content(cve_clicks, platform_clicks, cwe_clicks):
    # Determine which button was clicked
    if cve_clicks > platform_clicks and cve_clicks > cwe_clicks:
        # CVE Section: Show bar chart and scatter plot
        bar_chart = create_bar_chart(cwe_cve_count)
        scatter_plot = create_scatter_plot(df_scatter)
        return html.Div([
            html.H3('CVE-Related Visualizations'),
            dcc.Graph(figure=bar_chart),
            dcc.Graph(figure=scatter_plot)
        ])

    elif platform_clicks > cve_clicks and platform_clicks > cwe_clicks:
        # APT Section: Show stacked bar chart and heatmap
        stacked_bar_chart = create_stacked_bar_chart(apt_platform_counts)
        heatmap = create_heatmap(df_expanded)

        # Generate the folium map for regions (APT-related data)
        region_map = create_region_map(df)
        map_path = "region_map.html"
        region_map.save(map_path)

        return html.Div([
            html.H3("APT-Related Visualizations"),
            dcc.Graph(figure=stacked_bar_chart),
            dcc.Graph(figure=heatmap),
            html.Iframe(srcDoc=open(map_path, 'r').read(), width='100%', height='600')
        ])

    elif cwe_clicks > cve_clicks and cwe_clicks > platform_clicks:
        # CWE Section: Show heatmap and scatter plot
        heatmap = create_heatmap(df_expanded)
        scatter_plot = create_scatter_plot(df_scatter)
        return html.Div([
            html.H3('CWE-Related Visualizations'),
            dcc.Graph(figure=heatmap),
            dcc.Graph(figure=scatter_plot)
        ])


# Run the Dash app
if __name__ == '__main__':
    app.run_server(debug=True)

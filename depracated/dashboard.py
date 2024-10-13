import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import pandas as pd

# Import the scatter plot, heatmap, bar chart, and stacked bar chart from separate files
from diagram.CVECWEScatterPlot import create_cve_cwe_scatter_plot
from diagram.CWEPlatformHeatmap import create_cwe_platform_heatmap
from diagram.CVECWEBarChart import create_cve_cwe_bar_chart
from diagram.AptPlatformStackedBarChart import create_apt_platform_stacked_bar_chart
from diagram.AptRegionHeatMap import create_region_map
from diagram.CVETechniquesHeatmap import create_cve_technique_heatmap
from diagram.Apt36AssociatedTechniques import create_apt_c36_network_techniques
from diagram.Apt36AssociatedTechniquesTactics import create_apt_c36_network_techniques_tactics
from diagram.Apt36AssociatedTechniquesTactics_2 import create_apt_c36_network_techniques_tactics_2

# Load your dataset
excel = 'VisualAmended_v9.xlsx'
data_sheet = 'CleanedDataset'
df = pd.read_excel(excel, sheet_name=data_sheet)

# Standardize column names and prepare data
df.columns = df.columns.str.lower()
df_scatter = df[['cve', 'cwe-id', 'cvss-base-score']].dropna()
df_scatter['cwe_num'] = pd.factorize(df_scatter['cwe-id'])[0]
df_expanded = df.assign(platform=df['platforms'].str.split(',')).explode('platforms')
df_expanded['platforms'] = df_expanded['platforms'].str.strip()
df_expanded = df_expanded[df_expanded['cwe-id'] != 'UNKNOWN']

# Create data for the bar chart
df_filtered = df[['cve', 'cwe-id']].dropna()
df_filtered = df_filtered[(df_filtered['cwe-id'] != 'UNKNOWN') & (df_filtered['cwe-id'] != 'nvd-cwe-noinfo')]
cwe_cve_count = df_filtered.groupby('cwe-id').count().reset_index()
cwe_cve_count.columns = ['cwe-id', 'CVE Count']

# Group data for the stacked bar chart
apt_platform_counts = df_expanded.groupby(['apt', 'platforms']).size().reset_index(name='count')

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

    # Dropdown for CVE filtering (hidden by default)
    html.Div([
        dcc.Dropdown(
            id="cve-filter-dropdown",
            options=[{'label': cve, 'value': cve} for cve in df['cve'].unique()],
            multi=True,
            placeholder="Select CVE"
        )
    ], style={'display': 'none'}, id='cve-filter-container'),

    # Dropdown for APT filtering (hidden by default)
    html.Div([
        dcc.Dropdown(
            id="apt-filter-dropdown",
            options=[{'label': apt, 'value': apt} for apt in df['apt'].unique()],
            multi=True,
            placeholder="Select APT"
        )
    ], style={'display': 'none'}, id='apt-filter-container'),

    # Dropdown for CWE filtering (hidden by default)
    html.Div([
        dcc.Dropdown(
            id="cwe-filter-dropdown",
            options=[{'label': cwe, 'value': cwe} for cwe in df['cwe-id'].unique()],
            multi=True,
            placeholder="Select CWE"
        )
    ], style={'display': 'none'}, id='cwe-filter-container'),

    # Div to display the selected content dynamically
    html.Div(id='section-content', style={'marginTop': 20})
])

# Define the callback to update content based on the clicked button and selected dropdown filters
@app.callback(
    [Output('section-content', 'children'),
     Output('cve-filter-container', 'style'),
     Output('apt-filter-container', 'style'),
     Output('cwe-filter-container', 'style')],
    [Input('cve-button', 'n_clicks'),
     Input('platform-button', 'n_clicks'),
     Input('cwe-button', 'n_clicks'),
     Input('cve-filter-dropdown', 'value'),
     Input('apt-filter-dropdown', 'value'),
     Input('cwe-filter-dropdown', 'value')]
)
def render_content(cve_clicks, platform_clicks, cwe_clicks, selected_cves, selected_apts, selected_cwes):
    # Default: hide all dropdowns
    cve_dropdown_style = {'display': 'none'}
    apt_dropdown_style = {'display': 'none'}
    cwe_dropdown_style = {'display': 'none'}
    content = html.Div()

    # Check which button was clicked
    if cve_clicks > platform_clicks and cve_clicks > cwe_clicks:
        # Show CVE-Related Visualizations and CVE dropdown
        cve_dropdown_style = {'display': 'block'}  # Show CVE dropdown

        # Filter the data based on the selected CVEs
        if selected_cves:
            filtered_df = df[df['cve'].isin(selected_cves)]
            filtered_scatter = df_scatter[df_scatter['cve'].isin(selected_cves)]
        else:
            filtered_df = df
            filtered_scatter = df_scatter

        # Generate CVE-Related Visualizations
        bar_chart = create_cve_cwe_bar_chart(filtered_df)
        scatter_plot = create_cve_cwe_scatter_plot(filtered_scatter)
        heatmap_fig = create_cve_technique_heatmap(filtered_df)

        content = html.Div([
            html.H3('CVE-Related Visualizations'),
            dcc.Graph(figure=bar_chart),
            dcc.Graph(figure=scatter_plot),
            dcc.Graph(figure=heatmap_fig)
        ])

    elif platform_clicks > cve_clicks and platform_clicks > cwe_clicks:
        # Show APT-Related Visualizations and APT dropdown
        apt_dropdown_style = {'display': 'block'}  # Show APT dropdown

        # Filter the data based on the selected APTs
        if selected_apts:
            filtered_df = df[df['apt'].isin(selected_apts)]
            filtered_counts = filtered_df.groupby(['apt', 'platforms']).size().reset_index(name='count')
        else:
            filtered_counts = apt_platform_counts

        stacked_bar_chart = create_apt_platform_stacked_bar_chart(filtered_counts)

        # Generate the interactive network graphs for APT-C-36
        network_graph_apt36_technique = create_apt_c36_network_techniques(df)
        network_graph_apt36_technique_tactics = create_apt_c36_network_techniques_tactics(df)
        network_graph_apt36_technique_tactics_2 = create_apt_c36_network_techniques_tactics_2(df)

        content = html.Div([
            html.H3("APT-Related Visualizations"),
            dcc.Graph(figure=stacked_bar_chart),
            dcc.Graph(figure=network_graph_apt36_technique),
            dcc.Graph(figure=network_graph_apt36_technique_tactics),
            dcc.Graph(figure=network_graph_apt36_technique_tactics_2)
        ])

    elif cwe_clicks > cve_clicks and cwe_clicks > platform_clicks:
        # Show CWE-Related Visualizations and CWE dropdown
        cwe_dropdown_style = {'display': 'block'}  # Show CWE dropdown

        # Filter the data based on the selected CWEs
        if selected_cwes:
            filtered_df = df[df['cwe-id'].isin(selected_cwes)]
            filtered_scatter = df_scatter[df_scatter['cwe-id'].isin(selected_cwes)]
        else:
            filtered_df = df
            filtered_scatter = df_scatter

        heatmap = create_cwe_platform_heatmap(filtered_df)
        scatter_plot = create_cve_cwe_scatter_plot(filtered_scatter)

        content = html.Div([
            html.H3('CWE-Related Visualizations'),
            dcc.Graph(figure=heatmap),
            dcc.Graph(figure=scatter_plot)
        ])

    # Return the content and the dropdown styles
    return content, cve_dropdown_style, apt_dropdown_style, cwe_dropdown_style


# Run the Dash app
if __name__ == '__main__':
    app.run_server(debug=True)
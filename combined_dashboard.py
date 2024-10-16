from cProfile import label

import dash
from click import style
from dash import dcc, html
from dash.dependencies import Input, Output
import pandas as pd
import dash_bootstrap_components as dbc
from matplotlib import colors
# from requests.packages import target

from scipy.constants import value

# Import autonomous.py and manual.py (these should contain layouts and callback functions)
from autonomous import auto_layout, auto_callbacks
from manual import manual_layout, manual_callbacks
from novel import novel_layout, novel_callbacks
from summary import summary_layout

# Import the visualization functions from existing files
from diagram.CVECWEScatterPlot import create_cve_cwe_scatter_plot
from diagram.CWEPlatformHeatmap import create_cwe_platform_heatmap
from diagram.CVECWEBarChart import create_cve_cwe_bar_chart
from diagram.AptPlatformStackedBarChart import create_apt_platform_stacked_bar_chart
from diagram.CVETechniquesHeatmap import create_cve_technique_heatmap
from diagram.Apt36AssociatedTechniques import create_apt_network_techniques
from diagram.Apt36AssociatedTechniquesTactics import create_apt_network_techniques_tactics
from diagram.Apt36AssociatedTechniquesTactics_2 import create_apt_network_techniques_tactics_cve
from diagram.AptCVEBubbleChart import create_bubble_chart_apt_cvss
from diagram.AptCVEHeatMap import create_heatmap_apt_cvss
from diagram.PlatformIoCStackedBarChart import create_platform_ioc_stacked_bar_chart
from diagram.APTTechniqueTacticChart import create_techniques_tactics_chart

# Initialize the Dash app with callback exception suppression
app = dash.Dash(__name__, suppress_callback_exceptions=True, external_stylesheets=[dbc.themes.FLATLY])

# Load your dataset
excel = 'VisualAmended_v9.xlsx'
data_sheet = 'CleanedDataset'
df = pd.read_excel(excel, sheet_name=data_sheet)

# Standardize column names and prepare the dataset
df.columns = df.columns.str.lower()
df_scatter = df[['cve', 'cwe-id', 'cvss-base-score']].dropna()
df_scatter['cwe_num'] = pd.factorize(df_scatter['cwe-id'])[0]

# Split 'platforms' into separate rows
df['platforms'] = df['platforms'].fillna('')  # Replace NaNs with empty strings
df_expanded = df.assign(platform=df['platforms'].str.split(',')).explode('platform')
df_expanded['platform'] = df_expanded['platform'].str.strip()

# Filter valid platform names and create dropdown options
df_expanded = df_expanded[df_expanded['platform'].apply(lambda x: isinstance(x, str))]
platform_options = [{'label': platform, 'value': platform} for platform in df_expanded['platform'].unique()]

# Define color scheme
colors = {
    'background': '#f9f9f9',
    'text': '#333333'
}

# Define the layout of the dashboard
app.layout = html.Div(
    style={'font-family': 'Open Sans, sans-serif', 'backgroundColor': colors['background'], 'padding': '20px',
           'margin': '20px'}, children=[
        # Title with centered text
        html.H1("APT and Vulnerability Dashboard", style={'textAlign': 'center', 'color': colors['text']}),

        # Create tabs for switching between sections
        dcc.Tabs(id="tabs", value='summary-tab', children=[
            dcc.Tab(label='Summary', value='summary-tab', className='tab-style', selected_className='tab-selected'),
            dcc.Tab(label='Autonomous', value='auto-tab', className='tab-style', selected_className='tab-selected'),
            dcc.Tab(label='Manual', value='manual-tab', className='tab-style', selected_className='tab-selected'),
            dcc.Tab(label='Novelty', value='novelty-tab', className='tab-style', selected_className='tab-selected'),
            dcc.Tab(label='Visualisation', value='visualisation-tab', className='tab-style',
                    selected_className='tab-selected')
        ], className='tabs-container'),

        # Tab content container
        html.Div(id='tabs-content'),
    ])


# Callback to switch between tabs and render content dynamically
@app.callback(
    Output('tabs-content', 'children'),
    [Input('tabs', 'value')]
)
def render_content(tab):
    if tab == 'summary-tab':
        return summary_layout(df)  # Use summary_layout function for the summary tab
    elif tab == 'auto-tab':
        return auto_layout  # Autonomous tab content
    elif tab == 'manual-tab':
        return manual_layout(df)  # Manual tab content
    elif tab == 'novelty-tab':
        return novel_layout  # Novelty tab content
    elif tab == 'visualisation-tab':
        return html.Div([
            html.H2("Visualization Dashboard", style={'textAlign': 'center', 'color': colors['text']}),

            html.Div([
                html.Button('CVE-Related Visualizations', id='cve-button', n_clicks=0, className='btn-hover',
                            style={'margin-right': '10px'}),
                html.Button('APT-Related Visualizations', id='apt-button', n_clicks=0, className='btn-hover',
                            style={'margin-right': '10px'}),
                html.Button('CWE-Related Visualizations', id='cwe-button', n_clicks=0, className='btn-hover',
                            style={'margin-right': '10px'})
            ], style={'display': 'flex', 'justifyContent': 'center', 'alignItems': 'center', 'margin': '20px'}),

            # Dropdowns for filtering (hidden by default, shown based on selection)
            html.Div([dcc.Dropdown(id="cve-filter-dropdown",
                                   options=[{'label': cve, 'value': cve} for cve in df['cve'].unique()],
                                   multi=True, placeholder="Select CVE"),
                      dbc.Tooltip(
                          "Select multiple CVEs for filtering",
                          target="cve-filter-dropdown",
                          placement="bottom"
                      )], style={'display': 'none', 'margin-bottom': '20px', 'margin-top': '10px'},
                     id='cve-filter-container'),

            html.Div([dcc.Dropdown(id="apt-filter-dropdown",
                                   options=[{'label': apt, 'value': apt} for apt in df['apt'].unique()],
                                   multi=True, placeholder="Select APT"), dbc.Tooltip(
                "Select multiple CWEs for filtering",
                target="apt-filter-dropdown",
                placement="bottom"
            )], style={'display': 'none', 'margin-bottom': '20px', 'margin-top': '10px'},
                     id='apt-filter-container'),

            html.Div([dcc.Dropdown(id="cwe-filter-dropdown",
                                   options=[{'label': cwe, 'value': cwe} for cwe in df['cwe-id'].unique()],
                                   multi=True, placeholder="Select CWE"), dbc.Tooltip(
                "Select multiple APTs for filtering",
                target="cwe-filter-dropdown",
                placement="bottom"
            )], style={'display': 'none', 'margin-bottom': '20px', 'margin-top': '10px'},
                     id='cwe-filter-container'),

            html.Div([dcc.Dropdown(id="platform-selection-dropdown", options=platform_options, multi=True,
                                   placeholder="Select Platform")],
                     style={'display': 'none'}, id='platform-filter-container'),

            html.Div([
                dcc.Dropdown(
                    id="technique-selection-dropdown",
                    options=[{'label': technique, 'value': technique} for technique in df['technique-id'].unique()],
                    multi=True,
                    placeholder="Select technique"
                )
            ], style={'display': 'none'}, id='technique-filter-container'),

            # Visual content container
            html.Div(id='visual-content'),

        ], style={
            'padding': '10px'  # Add padding if necessary
        })


html.Footer("2024-HS2-COS70008-Technology Innovation Project",
            style={'textAlign': 'center', 'padding': '20px', 'backgroundColor': '#f9f9f9'})


# Visualisation Tab: Callback for buttons and filtering
@app.callback(
    [Output('visual-content', 'children'),
     Output('cve-filter-container', 'style'),
     Output('apt-filter-container', 'style'),
     Output('cwe-filter-container', 'style'),
     Output('platform-filter-container', 'style'),
     Output('technique-filter-container', 'style')],
    [Input('cve-button', 'n_clicks'),
     Input('apt-button', 'n_clicks'),
     Input('cwe-button', 'n_clicks')],
    [Input('cve-filter-dropdown', 'value'),
     Input('apt-filter-dropdown', 'value'),
     Input('cwe-filter-dropdown', 'value'),
     Input('platform-selection-dropdown', 'value'),
     Input('technique-selection-dropdown', 'value')]
)
def update_visual_content(cve_clicks, apt_clicks, cwe_clicks, selected_cves, selected_apts, selected_cwes,
                          selected_platforms, selected_technique):
    # Default: hide all dropdowns
    cve_dropdown_style = {'display': 'none'}
    apt_dropdown_style = {'display': 'none'}
    cwe_dropdown_style = {'display': 'none'}
    platform_dropdown_style = {'display': 'none'}
    technique_dropdown_style = {'display': 'none'}
    content = html.Div()  # Default empty content

    # Set default CVE clicks to 1 if none are clicked
    if cve_clicks is None and apt_clicks is None and cwe_clicks is None:
        cve_clicks = 1

    content = html.Div()  # Default empty content

    # Check which button was clicked and show the corresponding dropdown
    if cve_clicks and cve_clicks > apt_clicks and cve_clicks > cwe_clicks:
        # Show CVE-Related Visualizations and CVE dropdown
        cve_dropdown_style = {'display': 'block'}
        technique_dropdown_style = {'display': 'block'}

        # Filter the data based on the selected CVEs
        if selected_cves:
            filtered_df = df[df['cve'].isin(selected_cves)]
            filtered_scatter = df_scatter[df_scatter['cve'].isin(selected_cves)]
        else:
            filtered_df = df
            filtered_scatter = df_scatter

        if selected_technique:
            filtered_df = filtered_df[filtered_df['technique-id'].isin(selected_technique)]

        # Generate CVE-Related Visualizations
        bar_chart = create_cve_cwe_bar_chart(filtered_df)
        scatter_plot = create_cve_cwe_scatter_plot(filtered_scatter)
        heatmap_fig = create_cve_technique_heatmap(filtered_df, selected_technique)

        content = dbc.Container([
            html.H3('CVE-Related Visualizations',
                    style={'textAlign': 'center', 'color': colors['text'], 'margin': '20px'}),

            dbc.Row([
                dbc.Col(dcc.Graph(figure=heatmap_fig), width=12,
                        style={'border': '1px solid #ddd', 'padding': '10px', 'border-radius': '5px',
                               'box-shadow': '2px 2px 5px rgba(0,0,0,0.1)',
                               'margin-bottom': '10px'})
            ]),
            dbc.Row([
                dbc.Col(dcc.Graph(figure=bar_chart), width=6,
                        style={'border': '1px solid #ddd', 'padding': '10px', 'border-radius': '5px',
                               'box-shadow': '2px 2px 5px rgba(0,0,0,0.1)', 'width': '49%', 'margin-right': '1%',
                               'margin-bottom': '10px'}),
                dbc.Col(dcc.Graph(figure=scatter_plot), width=6,
                        style={'border': '1px solid #ddd', 'padding': '10px', 'border-radius': '5px',
                               'box-shadow': '2px 2px 5px rgba(0,0,0,0.1)', 'width': '49%', 'margin-left': '1%',
                               'margin-bottom': '10px'}),
            ]),

        ], fluid=True, style={'margin-bottom': '20px'})


    elif apt_clicks and apt_clicks > cve_clicks and apt_clicks > cwe_clicks:
        # Show APT-Related Visualizations and APT dropdown
        apt_dropdown_style = {'display': 'block'}
        platform_dropdown_style = {'display': 'block'}

        # Filter the data based on the selected APTs and platforms
        if selected_apts:
            filtered_df = df[df['apt'].isin(selected_apts)]
        else:
            filtered_df = df

        if selected_platforms:
            filtered_df_platforms = filtered_df[filtered_df['platforms'].isin(selected_platforms)]

        # Generate APT-related visualizations
        stacked_bar_chart = create_apt_platform_stacked_bar_chart(filtered_df, selected_apts, selected_platforms)
        network_graph_apt36_technique = create_apt_network_techniques(filtered_df, selected_apts)
        network_graph_apt36_technique_tactics = create_apt_network_techniques_tactics(filtered_df, selected_apts)
        network_graph_apt36_technique_tactics_2 = create_apt_network_techniques_tactics_cve(filtered_df, selected_apts)
        heatmap_apt_cvss = create_heatmap_apt_cvss(filtered_df, selected_apts)
        bubble_apt_cvss = create_bubble_chart_apt_cvss(filtered_df, selected_apts)
        chart_apt_technique_tactic = create_techniques_tactics_chart(filtered_df, selected_apts)

        # Use grid layout for visualizations

        content = dbc.Container([
            html.H3("APT-Related Visualizations",
                    style={'textAlign': 'center', 'color': colors['text'], 'margin': '20px'}),
            dbc.Row([
                dbc.Col(dcc.Graph(figure=stacked_bar_chart), width=6,
                        style={'border': '1px solid #ddd', 'padding': '10px', 'border-radius': '5px',
                               'box-shadow': '2px 2px 5px rgba(0,0,0,0.1)', 'width': '49%', 'margin-right': '1%',
                               'margin-bottom': '10px'}),
                dbc.Col(dcc.Graph(figure=network_graph_apt36_technique_tactics), width=6,
                        style={'border': '1px solid #ddd', 'padding': '10px', 'border-radius': '5px',
                               'box-shadow': '2px 2px 5px rgba(0,0,0,0.1)', 'width': '49%', 'margin-left': '1%',
                               'margin-bottom': '10px'}),
            ]),
            dbc.Row([
                dbc.Col(dcc.Graph(figure=network_graph_apt36_technique_tactics_2), width=6,
                        style={'border': '1px solid #ddd', 'padding': '10px', 'border-radius': '5px',
                               'box-shadow': '2px 2px 5px rgba(0,0,0,0.1)', 'width': '49%', 'margin-right': '1%',
                               'margin-bottom': '10px'}),
                dbc.Col(dcc.Graph(figure=chart_apt_technique_tactic), width=6,
                        style={'border': '1px solid #ddd', 'padding': '10px', 'border-radius': '5px',
                               'box-shadow': '2px 2px 5px rgba(0,0,0,0.1)', 'width': '49%', 'margin-left': '1%',
                               'margin-bottom': '10px'}),
            ]),
            dbc.Row([
                dbc.Col(dcc.Graph(figure=network_graph_apt36_technique), width=12,
                        style={'border': '1px solid #ddd', 'padding': '10px', 'border-radius': '5px',
                               'box-shadow': '2px 2px 5px rgba(0,0,0,0.1)', 'margin-bottom': '10px'}),
            ]),
            dbc.Row([
                dbc.Col(dcc.Graph(figure=heatmap_apt_cvss), width=6,
                        style={'border': '1px solid #ddd', 'padding': '10px', 'border-radius': '5px',
                               'box-shadow': '2px 2px 5px rgba(0,0,0,0.1)', 'width': '49%', 'margin-right': '1%',
                               'margin-bottom': '10px'}),
                dbc.Col(dcc.Graph(figure=bubble_apt_cvss), width=6,
                        style={'border': '1px solid #ddd', 'padding': '10px', 'border-radius': '5px',
                               'box-shadow': '2px 2px 5px rgba(0,0,0,0.1)', 'width': '49%', 'margin-left': '1%',
                               'margin-bottom': '10px'}),
            ])
        ], fluid=True, style={'margin-bottom': '20px'})

    elif cwe_clicks and cwe_clicks > cve_clicks and cwe_clicks > apt_clicks:
        # Show CWE-Related Visualizations and CWE + platform dropdowns
        cwe_dropdown_style = {'display': 'block'}
        platform_dropdown_style = {'display': 'block'}

        # Filter the data based on the selected CWEs and platforms
        if selected_cwes:
            filtered_df = df_expanded[df_expanded['cwe-id'].isin(selected_cwes)]
        else:
            filtered_df = df_expanded

        if selected_platforms:
            filtered_df = filtered_df[filtered_df['platform'].isin(selected_platforms)]

        # Generate CWE-related visualizations
        cwe_platform_heatmap = create_cwe_platform_heatmap(filtered_df, selected_cwes, selected_platforms)
        cve_cwe_scatter_plot = create_cve_cwe_scatter_plot(df_scatter)
        platform_ioc_stacked_bar_chart = create_platform_ioc_stacked_bar_chart(filtered_df, selected_platforms)

        content = dbc.Container([
            html.H3('CWE-Related Visualizations',
                    style={'textAlign': 'center', 'color': colors['text'], 'margin': '20px'}),

            dbc.Row([
                dbc.Col(dcc.Graph(figure=cwe_platform_heatmap), width=6,
                        style={'border': '1px solid #ddd', 'padding': '10px', 'border-radius': '5px',
                               'box-shadow': '2px 2px 5px rgba(0,0,0,0.1)', 'width': '49%', 'margin-right': '1%',
                               'margin-bottom': '10px'}),
                dbc.Col(dcc.Graph(figure=cve_cwe_scatter_plot), width=6,
                        style={'border': '1px solid #ddd', 'padding': '10px', 'border-radius': '5px',
                               'box-shadow': '2px 2px 5px rgba(0,0,0,0.1)', 'width': '49%', 'margin-left': '1%',
                               'margin-bottom': '10px'}),
            ]),

            dbc.Row([
                dbc.Col(dcc.Graph(figure=platform_ioc_stacked_bar_chart), width=12,
                        style={'border': '1px solid #ddd', 'padding': '10px', 'border-radius': '5px',
                               'box-shadow': '2px 2px 5px rgba(0,0,0,0.1)', 'margin-bottom': '10px'})
            ])
        ], fluid=True, style={'margin-bottom': '20px'})

    # Always return the content and dropdown styles (even if no buttons are clicked)
    return content, cve_dropdown_style, apt_dropdown_style, cwe_dropdown_style, platform_dropdown_style, technique_dropdown_style


# Register callbacks from autonomous and manual files
auto_callbacks(app)
manual_callbacks(app)
novel_callbacks(app)  # Add this line to register novel callbacks

# Run the app
if __name__ == '__main__':
    app.run_server(debug=True)

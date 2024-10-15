import plotly.graph_objs as go
import plotly.express as px
import plotly.graph_objects as go

# Function to create the pie chart for top 10 APT Groups by Number of Techniques
def create_pie_chart(data):
    # Group data by APT group and count techniques
    apt_technique_counts = data.groupby('apt')['technique-id'].nunique().reset_index()

    # Rename the columns for clarity
    apt_technique_counts.columns = ['apt', 'Technique Count']

    # Sort and get the top 10 APT groups based on technique count
    top_10_apts = apt_technique_counts.nlargest(10, 'Technique Count')

    # Create the pie chart
    fig = go.Figure(data=[go.Pie(
        labels=top_10_apts['apt'],
        values=top_10_apts['Technique Count'],
        hoverinfo='label+percent',
        textinfo='value',
        marker=dict(colors=px.colors.sequential.Sunset)  # Use Plotly's built-in color scale
    )])

    # Update the layout of the pie chart
    fig.update_layout(
        title='Top 10 APTs by Techniques Used',
        showlegend=True,
        legend=dict(
            orientation="h",  # Horizontal legend
            yanchor="bottom",  # Place legend at the bottom
            y=-0.2,  # Adjust this value to move the legend further down
            xanchor="center",
            x=0.5  # Center the legend
        )
    )

    return fig


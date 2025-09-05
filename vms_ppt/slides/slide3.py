import time
from pptx.util import Inches
from pptx import Presentation
from .slide_utils import SlideUtils

def create_slide3(prs: Presentation, slide3_data):
    start_time = time.time()
    slide_layout = prs.slide_layouts[6]
    slide = prs.slides.add_slide(slide_layout)
    
    # Create title bar
    SlideUtils.create_title_bar(slide, prs, slide3_data["title"])
    
    # Get layout parameters
    layout = SlideUtils.get_standard_layout_params(prs)
    
    # Calculate totals
    table1_totals = SlideUtils.calculate_column_totals(slide3_data["table1"]["rows"], 5, "Grand Total")
    table2_totals = SlideUtils.calculate_column_totals(slide3_data["table2"]["rows"], 5, "Grand Total")
    
    # Create tables
    _create_confirmed_threats_table(slide, slide3_data, table1_totals, layout)
    _create_potential_threats_table(slide, slide3_data, table2_totals, layout)
    _create_risk_impact_table(slide, slide3_data, layout)
    
    # Print results
    _print_slide3_results(start_time, table1_totals, table2_totals)
    return time.time() - start_time

def _create_confirmed_threats_table(slide, slide3_data, totals, layout):
    """Create confirmed threats table"""
    SlideUtils.create_subtitle(slide, layout['table_left'], Inches(0.8), layout['max_table_width'], slide3_data["subtitle1"])
    
    data_with_totals = slide3_data["table1"]["rows"] + [totals]
    table = SlideUtils.create_table_with_headers(slide, len(data_with_totals) + 1, 5,
                                               layout['table_left'], Inches(1.2), layout['max_table_width'], Inches(2.0))
    
    column_widths = [Inches(6.95), Inches(1.39), Inches(1.11), Inches(1.11), Inches(1.76)]
    SlideUtils.set_table_column_widths(table, column_widths)
    SlideUtils.set_table_row_heights(table, Inches(0.35), Inches(0.3))
    SlideUtils.format_header_row(table, slide3_data["table1"]["columns"])
    SlideUtils.populate_table_data(table, data_with_totals)

def _create_potential_threats_table(slide, slide3_data, totals, layout):
    """Create potential threats table"""
    SlideUtils.create_subtitle(slide, layout['table_left'], Inches(3.4), layout['max_table_width'], slide3_data["subtitle2"])
    
    data_with_totals = slide3_data["table2"]["rows"] + [totals]
    table = SlideUtils.create_table_with_headers(slide, len(data_with_totals) + 1, 5,
                                               layout['table_left'], Inches(3.8), layout['max_table_width'], Inches(2.4))
    
    column_widths = [Inches(6.95), Inches(1.39), Inches(1.11), Inches(1.11), Inches(1.76)]
    SlideUtils.set_table_column_widths(table, column_widths)
    SlideUtils.set_table_row_heights(table, Inches(0.35), Inches(0.3))
    SlideUtils.format_header_row(table, slide3_data["table2"]["columns"])
    SlideUtils.populate_table_data(table, data_with_totals)

def _create_risk_impact_table(slide, slide3_data, layout):
    """Create risk and impact table"""
    table_data = {
        "columns": ["Risk", "Impact"],
        "rows": [[slide3_data["footnote"]["Risk"], slide3_data["footnote"]["Impact"]]]
    }
    
    table = SlideUtils.create_table_with_headers(slide, 2, 2, layout['table_left'], Inches(6.4), 
                                               layout['max_table_width'], Inches(0.8))
    SlideUtils.set_table_column_widths(table, [Inches(6.165), Inches(6.165)])
    SlideUtils.set_table_row_heights(table, Inches(0.35), Inches(0.4))
    SlideUtils.format_header_row(table, table_data["columns"])
    SlideUtils.populate_table_data(table, table_data["rows"])

def _print_slide3_results(start_time, table1_totals, table2_totals):
    """Print slide 3 results"""
    runtime = time.time() - start_time
    print(f"Slide 3 created successfully!")
    print(f"Confirmed Threats Total - Critical: {table1_totals[1]}, High: {table1_totals[2]}, Medium: {table1_totals[3]}, Grand Total: {table1_totals[4]}")
    print(f"Potential Threats Total - Critical: {table2_totals[1]}, High: {table2_totals[2]}, Medium: {table2_totals[3]}, Grand Total: {table2_totals[4]}")
    print(f"Runtime: {runtime:.4f} seconds")

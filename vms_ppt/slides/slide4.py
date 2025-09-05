from pptx import Presentation
import time
from pptx.util import Inches
from .slide_utils import SlideUtils

def create_slide4(prs: Presentation, slide4_data):
    start_time = time.time()
    slide_layout = prs.slide_layouts[6]
    slide = prs.slides.add_slide(slide_layout)
    
    # Create title bar
    SlideUtils.create_title_bar(slide, prs, slide4_data["title"])
    
    # Get layout parameters
    layout = SlideUtils.get_standard_layout_params(prs)
    
    # Calculate totals
    table1_totals = SlideUtils.calculate_column_totals(slide4_data["table1"]["rows"], 6, "Grand Total")
    table2_totals = SlideUtils.calculate_column_totals(slide4_data["table2"]["rows"], 4, "Grand Total")
    
    # Create tables
    _create_software_update_table(slide, slide4_data, table1_totals, layout)
    _create_os_hardening_table(slide, slide4_data, table2_totals, layout)
    
    # Print results
    _print_slide4_results(start_time, table1_totals, table2_totals)
    return time.time() - start_time

def _create_software_update_table(slide, slide4_data, totals, layout):
    """Create software update/uninstallation table"""
    SlideUtils.create_subtitle(slide, layout['table_left'], Inches(0.8), layout['max_table_width'], slide4_data["subtitle1"])
    
    data_with_totals = slide4_data["table1"]["rows"] + [totals]
    table = SlideUtils.create_table_with_headers(slide, len(data_with_totals) + 1, 6,
                                               layout['table_left'], Inches(1.2), layout['max_table_width'], Inches(2.8))
    
    column_widths = [Inches(3.5), Inches(1.5), Inches(1.5), Inches(1.5), Inches(1.5), Inches(2.8)]
    SlideUtils.set_table_column_widths(table, column_widths)
    SlideUtils.set_table_row_heights(table, Inches(0.4), Inches(0.3))
    SlideUtils.format_header_row(table, slide4_data["table1"]["columns"])
    SlideUtils.populate_table_data(table, data_with_totals)

def _create_os_hardening_table(slide, slide4_data, totals, layout):
    """Create OS hardening/configuration table"""
    table_top = Inches(4.2)
    SlideUtils.create_subtitle(slide, layout['table_left'], table_top, layout['max_table_width'], slide4_data["subtitle2"])
    
    data_with_totals = slide4_data["table2"]["rows"] + [totals]
    table = SlideUtils.create_table_with_headers(slide, len(data_with_totals) + 1, 4,
                                               layout['table_left'], table_top + Inches(0.4), layout['max_table_width'], Inches(2.0))
    
    column_widths = [Inches(8.5), Inches(1.5), Inches(1.5), Inches(1.8)]
    SlideUtils.set_table_column_widths(table, column_widths)
    SlideUtils.set_table_row_heights(table, Inches(0.4), Inches(0.3))
    SlideUtils.format_header_row(table, slide4_data["table2"]["columns"])
    SlideUtils.populate_table_data(table, data_with_totals)

def _print_slide4_results(start_time, table1_totals, table2_totals):
    """Print slide 4 results"""
    runtime = time.time() - start_time
    print(f"Slide 4 created successfully!")
    print(f"Software Exploits Total - Critical: {table1_totals[1]}, High: {table1_totals[2]}, Immediate: {table1_totals[3]}, Medium: {table1_totals[4]}, Grand Total: {table1_totals[5]}")
    print(f"OS Hardening Exploits Total - Critical: {table2_totals[1]}, Medium: {table2_totals[2]}, Grand Total: {table2_totals[3]}")
    print(f"Runtime: {runtime:.4f} seconds")

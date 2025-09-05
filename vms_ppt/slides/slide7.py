from pptx import Presentation
import time
from pptx.util import Inches
from .slide_utils import SlideUtils

def create_slide7(prs: Presentation, slide7_data):
    start_time = time.time()
    slide_layout = prs.slide_layouts[6]
    slide = prs.slides.add_slide(slide_layout)
    
    # Create title bar
    SlideUtils.create_title_bar(slide, prs, slide7_data["title"])
    
    # Get layout parameters
    layout = SlideUtils.get_standard_layout_params(prs)
    
    # Calculate totals
    totals = SlideUtils.calculate_column_totals(slide7_data["table"]["rows"], len(slide7_data["table"]["columns"]), "Grand Total")
    
    # Create main table
    _create_patching_details_table(slide, slide7_data, totals, layout)
    
    # Print results
    _print_slide7_results(start_time, totals)
    return time.time() - start_time

def _create_patching_details_table(slide, slide7_data, totals, layout):
    """Create stage 1 patching details table"""
    filtered_rows = [row for row in slide7_data["table"]["rows"] if "Total" not in row[0]]
    data_with_totals = filtered_rows + [totals]
    
    table = SlideUtils.create_table_with_headers(slide, len(data_with_totals) + 1, len(slide7_data["table"]["columns"]),
                                               layout['table_left'], Inches(1.0), layout['max_table_width'], Inches(5.0))
    
    column_widths = [Inches(5.55), Inches(1.23), Inches(1.54), Inches(1.23), Inches(1.23), Inches(1.54)]
    SlideUtils.set_table_column_widths(table, column_widths)
    SlideUtils.set_table_row_heights(table, Inches(0.4), Inches(0.3))
    SlideUtils.format_header_row(table, slide7_data["table"]["columns"])
    SlideUtils.populate_table_data(table, data_with_totals)

def _print_slide7_results(start_time, totals):
    """Print slide 7 results"""
    runtime = time.time() - start_time
    print(f"Slide 7 created successfully!")
    print(f"Calculated Totals - Immediate: {totals[1]}, Critical: {totals[2]}, High: {totals[3]}, Medium: {totals[4]}, Grand Total: {totals[5]}")
    print(f"Runtime: {runtime:.4f} seconds")

from pptx import Presentation
from pptx.util import Inches
import time
from .slide_utils import SlideUtils

def create_slide8(prs: Presentation, slide8_data):
    start_time = time.time()
    slide_layout = prs.slide_layouts[6]
    slide = prs.slides.add_slide(slide_layout)
    
    # Create title bar
    SlideUtils.create_title_bar(slide, prs, slide8_data["title"])
    
    # Calculate totals
    totals = SlideUtils.calculate_column_totals(slide8_data["table"]["rows"], len(slide8_data["table"]["columns"]), "Grand Total")
    
    # Create main table
    _create_software_uninstall_table(slide, slide8_data, totals, prs)
    
    # Print results
    _print_slide8_results(start_time, totals)
    return time.time() - start_time

def _create_software_uninstall_table(slide, slide8_data, totals, prs):
    """Create software update/uninstallation table"""
    filtered_rows = [row for row in slide8_data["table"]["rows"] if "Total" not in row[0]]
    data_with_totals = filtered_rows + [totals]
    
    table = SlideUtils.create_table_with_headers(slide, len(data_with_totals) + 1, len(slide8_data["table"]["columns"]),
                                               Inches(0.3), Inches(1.0), prs.slide_width - Inches(0.6), Inches(4.5))
    
    column_widths = [Inches(3.5), Inches(1.5), Inches(1.5), Inches(1.5), Inches(1.5), Inches(2.0)]
    SlideUtils.set_table_column_widths(table, column_widths)
    SlideUtils.set_table_row_heights(table, Inches(0.4), Inches(0.3))
    SlideUtils.format_header_row(table, slide8_data["table"]["columns"])
    SlideUtils.populate_table_data(table, data_with_totals)

def _print_slide8_results(start_time, totals):
    """Print slide 8 results"""
    runtime = time.time() - start_time
    print(f"Slide 8 created successfully!")
    print(f"Calculated Totals - Critical: {totals[1]}, High: {totals[2]}, Immediate: {totals[3]}, Medium: {totals[4]}, Grand Total: {totals[5]}")
    print(f"Runtime: {runtime:.4f} seconds")

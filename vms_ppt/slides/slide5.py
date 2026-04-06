from pptx import Presentation
import time
from pptx.util import Inches
from .slide_utils import SlideUtils


def create_slide5(prs: Presentation, slide5_data):
    start_time = time.time()
    slide_layout = prs.slide_layouts[6]
    slide = prs.slides.add_slide(slide_layout)
    
    # Create title bar
    SlideUtils.create_title_bar(slide, prs, slide5_data["title"])
    
    # Get layout parameters
    layout = SlideUtils.get_standard_layout_params(prs)
    
    # Create subtitle
    SlideUtils.create_subtitle(slide, layout['table_left'], Inches(0.8), layout['max_table_width'], slide5_data["subtitle"])
    
    # Calculate totals
    totals = SlideUtils.calculate_column_totals(slide5_data["table"]["rows"], len(slide5_data["table"]["columns"]), "Grand Total")
    
    # Create main table
    _create_os_vulnerability_table(slide, slide5_data, totals, layout)
    
    # Print results
    _print_slide5_results(start_time, totals)
    return time.time() - start_time


def _create_os_vulnerability_table(slide, slide5_data, totals, layout):
    """Create operating system vulnerability table with optimized column widths"""
    filtered_rows = [row for row in slide5_data["table"]["rows"] if "Total" not in row[0]]
    data_with_totals = filtered_rows + [totals]
    
    table = SlideUtils.create_table_with_headers(slide, len(data_with_totals) + 1, len(slide5_data["table"]["columns"]),
                                               layout['table_left'], Inches(1.2), layout['max_table_width'], Inches(4.5))
    
    # FIXED COLUMN WIDTHS - Reduced to fit within slide bounds
    # Total width adjusted to approximately 12.3 inches (within standard 13.33" slide width)
    column_widths = [
        Inches(5),   # Operating System (reduced from 6.5)
        Inches(1.3),   # Critical (reduced from 1.5) 
        Inches(1.3),   # High (reduced from 1.5)
        Inches(1.3),   # Medium (reduced from 1.5)
        Inches(1.3)    # Grand Total (increased slightly from 1.3)
    ]
    
    SlideUtils.set_table_column_widths(table, column_widths)
    SlideUtils.set_table_row_heights(table, Inches(0.35), Inches(0.3))  # Slightly reduced row height
    SlideUtils.format_header_row(table, slide5_data["table"]["columns"])
    SlideUtils.populate_table_data(table, data_with_totals)


def _print_slide5_results(start_time, totals):
    """Print slide 5 results"""
    runtime = time.time() - start_time
    print(f"Slide 5 created successfully!")
    print(f"Calculated Totals - Critical: {totals[1]}, High: {totals[2]}, Immediate: {totals[3]}, Grand Total: {totals[4]}")
    print(f"Runtime: {runtime:.4f} seconds")

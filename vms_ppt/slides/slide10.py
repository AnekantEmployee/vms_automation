import time
from pptx import Presentation
from pptx.util import Inches
from .slide_utils import SlideUtils

def create_slide10(prs: Presentation, slide10_data):
    start_time = time.time()
    slide_layout = prs.slide_layouts[6]
    slide = prs.slides.add_slide(slide_layout)
    
    # Create title bar
    SlideUtils.create_title_bar(slide, prs, slide10_data["title"])
    
    # Get layout parameters
    layout = SlideUtils.get_standard_layout_params(prs)
    
    # Calculate totals
    totals = _calculate_hardening_totals(slide10_data["table"]["rows"])
    
    # Create main table
    _create_hardening_table(slide, slide10_data, totals, layout)
    
    # Print results
    _print_slide10_results(start_time, totals)
    return time.time() - start_time

def _calculate_hardening_totals(rows):
    """Calculate hardening configuration totals"""
    total_critical, total_medium = 0, 0
    for row in rows:
        if "Grand Total" not in row[0]:
            critical_val = row[1].strip() if row[1] else "0"
            medium_val = row[2].strip() if row[2] else "0"
            
            if critical_val.isdigit():
                total_critical += int(critical_val)
            if medium_val.isdigit():
                total_medium += int(medium_val)
    
    grand_total = total_critical + total_medium
    return ["Grand Total", str(total_critical), str(total_medium), str(grand_total)]

def _create_hardening_table(slide, slide10_data, totals, layout):
    """Create OS hardening/configuration table"""
    filtered_rows = [row for row in slide10_data["table"]["rows"] if "Grand Total" not in row[0]]
    data_with_totals = filtered_rows + [totals]
    
    table = SlideUtils.create_table_with_headers(slide, len(data_with_totals) + 1, 4,
                                               layout['table_left'], Inches(1.0), layout['max_table_width'], Inches(4.5))
    
    column_widths = [Inches(7), Inches(1.5), Inches(1.5), Inches(1.5)]
    SlideUtils.set_table_column_widths(table, column_widths)
    SlideUtils.set_table_row_heights(table, Inches(0.4), Inches(0.35))
    SlideUtils.format_header_row(table, slide10_data["table"]["columns"])
    SlideUtils.populate_table_data(table, data_with_totals)

def _print_slide10_results(start_time, totals):
    """Print slide 10 results"""
    runtime = time.time() - start_time
    print(f"Slide 10 created successfully!")
    print(f"Calculated Totals - Critical: {totals[1]}, Medium: {totals[2]}, Grand Total: {totals[3]}")
    print(f"Runtime: {runtime:.4f} seconds")

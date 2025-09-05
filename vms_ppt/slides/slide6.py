from pptx import Presentation
from pptx.util import Inches
import time
from .slide_utils import SlideUtils

def create_slide6(prs: Presentation, slide6_data):
    start_time = time.time()
    slide_layout = prs.slide_layouts[6]
    slide = prs.slides.add_slide(slide_layout)
    
    # Create title bar
    SlideUtils.create_title_bar(slide, prs, slide6_data["title"])
    
    # Get layout parameters
    layout = SlideUtils.get_standard_layout_params(prs)
    
    # Calculate totals
    stage1_totals = _calculate_stage_totals(slide6_data['stage1_table']['rows'])
    stage2_totals = _calculate_stage2_totals(slide6_data['stage2_table']['rows'])
    
    # Create tables
    _create_stage1_table(slide, slide6_data, stage1_totals, layout)
    _create_stage2_table(slide, slide6_data, stage2_totals, layout)
    
    # Create footnote
    SlideUtils.create_footnote(slide, layout['table_left'], Inches(6.8), layout['max_table_width'], slide6_data["footnote"])
    
    # Print results
    _print_slide6_results(start_time, stage1_totals, stage2_totals)
    return time.time() - start_time

def _calculate_stage_totals(rows):
    """Calculate stage 1 totals"""
    total, remediation, balance = 0, 0, 0
    for row in rows:
        if row[1] != 'Total':
            total += int(row[2]) if str(row[2]).isdigit() else 0
            remediation += int(row[3]) if str(row[3]).isdigit() else 0
            balance += int(row[4]) if str(row[4]).isdigit() else 0
    return ["", "Total", str(total), str(remediation), str(balance), ""]

def _calculate_stage2_totals(rows):
    """Calculate stage 2 totals"""
    total, balance = 0, 0
    for row in rows:
        if row[1] != 'Total':
            total += int(row[2]) if str(row[2]).isdigit() else 0
            balance += int(row[4]) if str(row[4]).isdigit() else 0
    return ["", "Total", str(total), "TBD", str(balance), ""]

def _create_stage1_table(slide, slide6_data, totals, layout):
    """Create stage 1 remediation table"""
    SlideUtils.create_subtitle(slide, layout['table_left'], Inches(0.8), layout['max_table_width'], slide6_data["stage1_title"])
    
    data_with_totals = slide6_data["stage1_table"]["rows"] + [totals]
    table = SlideUtils.create_table_with_headers(slide, len(data_with_totals) + 1, 6,
                                               layout['table_left'], Inches(1.2), layout['max_table_width'], Inches(2.2))
    
    column_widths = [Inches(0.5), Inches(4.0), Inches(1.5), Inches(2.0), Inches(1.5), Inches(1.8)]
    SlideUtils.set_table_column_widths(table, column_widths)
    SlideUtils.set_table_row_heights(table, Inches(0.4), Inches(0.35))
    SlideUtils.format_header_row(table, slide6_data["stage1_table"]["columns"])
    SlideUtils.populate_table_data(table, data_with_totals)

def _create_stage2_table(slide, slide6_data, totals, layout):
    """Create stage 2 remediation table"""
    table_top = Inches(3.8)
    SlideUtils.create_subtitle(slide, layout['table_left'], table_top, layout['max_table_width'], slide6_data["stage2_title"])
    
    data_with_totals = slide6_data["stage2_table"]["rows"] + [totals]
    table = SlideUtils.create_table_with_headers(slide, len(data_with_totals) + 1, 6,
                                               layout['table_left'], table_top + Inches(0.4), layout['max_table_width'], Inches(2.2))
    
    column_widths = [Inches(0.5), Inches(4.0), Inches(1.5), Inches(2.0), Inches(1.5), Inches(1.8)]
    SlideUtils.set_table_column_widths(table, column_widths)
    SlideUtils.set_table_row_heights(table, Inches(0.4), Inches(0.35))
    SlideUtils.format_header_row(table, slide6_data["stage2_table"]["columns"])
    SlideUtils.populate_table_data(table, data_with_totals)

def _print_slide6_results(start_time, stage1_totals, stage2_totals):
    """Print slide 6 results"""
    runtime = time.time() - start_time
    print(f"Slide 6 created successfully!")
    print(f"Stage 1 Calculated Totals - Total: {stage1_totals[2]}, Target: {stage1_totals[3]}, Balance: {stage1_totals[4]}")
    print(f"Stage 2 Calculated Totals - Total: {stage2_totals[2]}, Balance: {stage2_totals[4]}")
    print(f"Runtime: {runtime:.4f} seconds")
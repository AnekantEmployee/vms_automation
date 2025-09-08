import time
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx import Presentation
from .slide_utils import SlideUtils


def create_slide3(prs: Presentation, slide3_data):
    """Create slide(s) for Critical & High Risk Vulnerabilities with pagination"""
    start_time = time.time()
    
    # Check if we need to split into multiple slides
    critical_vulns = slide3_data.get("table1", {}).get("rows", [])
    high_vulns = slide3_data.get("table2", {}).get("rows", [])
    
    slides_created = []
    
    # Define max rows per slide (accounting for table headers and layout)
    MAX_ROWS_PER_SLIDE = 12  # Adjust based on your slide layout constraints
    
    # Create Critical Vulnerability slides
    critical_slides = _create_critical_vulnerability_slides(prs, slide3_data, critical_vulns, MAX_ROWS_PER_SLIDE)
    slides_created.extend(critical_slides)
    
    # Create High Vulnerability slides  
    high_slides = _create_high_vulnerability_slides(prs, slide3_data, high_vulns, MAX_ROWS_PER_SLIDE)
    slides_created.extend(high_slides)
    
    # Create combined summary slide if we have multiple slides
    if len(slides_created) > 1:
        summary_slide = _create_vulnerability_summary_slide(prs, slide3_data, critical_vulns, high_vulns)
        slides_created.insert(0, summary_slide)  # Add summary as first slide
    
    # Print results
    _print_slide3_results(start_time, critical_vulns, high_vulns, len(slides_created))
    
    return slides_created, time.time() - start_time


def _create_critical_vulnerability_slides(prs, slide3_data, critical_vulns, max_rows):
    """Create one or more slides for critical vulnerabilities"""
    if not critical_vulns or len(critical_vulns) == 0:
        return []
    
    slides_created = []
    critical_chunks = list(_split_rows_for_slides(critical_vulns, max_rows))
    
    for chunk_idx, chunk in enumerate(critical_chunks):
        slide_layout = prs.slide_layouts[6]
        slide = prs.slides.add_slide(slide_layout)
        
        # Create title - add page number if multiple slides
        title = f"{slide3_data['title']} - Critical Vulnerabilities"
        if len(critical_chunks) > 1:
            title += f" (Page {chunk_idx + 1} of {len(critical_chunks)})"
        
        SlideUtils.create_title_bar(slide, prs, title)
        
        # Get layout parameters
        layout = SlideUtils.get_standard_layout_params(prs)
        
        # Create subtitle
        subtitle = f"Critical Severity Vulnerabilities ({len(critical_vulns)} total)"
        if len(critical_chunks) > 1:
            start_idx = chunk_idx * max_rows + 1
            end_idx = min((chunk_idx + 1) * max_rows, len(critical_vulns))
            subtitle += f" - Items {start_idx}-{end_idx}"
        
        SlideUtils.create_subtitle(slide, layout['table_left'], Inches(0.8), layout['max_table_width'], subtitle)
        
        # Calculate totals for this chunk
        chunk_totals = SlideUtils.calculate_column_totals(chunk, 5, "Page Total")
        
        # Create table
        data_with_totals = chunk + [chunk_totals]
        table = SlideUtils.create_table_with_headers(slide, len(data_with_totals) + 1, 5,
                                                   layout['table_left'], Inches(1.2), 
                                                   layout['max_table_width'], Inches(4.8))
        
        column_widths = [Inches(6.95), Inches(1.39), Inches(1.11), Inches(1.11), Inches(1.76)]
        SlideUtils.set_table_column_widths(table, column_widths)
        SlideUtils.set_table_row_heights(table, Inches(0.35), Inches(0.32))
        SlideUtils.format_header_row(table, slide3_data["table1"]["columns"])
        SlideUtils.populate_table_data(table, data_with_totals)
        
        # Add footer with navigation info
        if len(critical_chunks) > 1:
            footer_text = f"Critical Vulnerabilities - Page {chunk_idx + 1} of {len(critical_chunks)}"
            SlideUtils.create_footnote(slide, layout['table_left'], Inches(6.2), 
                                     layout['max_table_width'], footer_text, font_size=10)
        
        slides_created.append(slide)
    
    return slides_created


def _create_high_vulnerability_slides(prs, slide3_data, high_vulns, max_rows):
    """Create one or more slides for high vulnerabilities"""
    if not high_vulns or len(high_vulns) == 0:
        return []
    
    slides_created = []
    high_chunks = list(_split_rows_for_slides(high_vulns, max_rows))
    
    for chunk_idx, chunk in enumerate(high_chunks):
        slide_layout = prs.slide_layouts[6]
        slide = prs.slides.add_slide(slide_layout)
        
        # Create title - add page number if multiple slides
        title = f"{slide3_data['title']} - High Vulnerabilities"
        if len(high_chunks) > 1:
            title += f" (Page {chunk_idx + 1} of {len(high_chunks)})"
        
        SlideUtils.create_title_bar(slide, prs, title)
        
        # Get layout parameters
        layout = SlideUtils.get_standard_layout_params(prs)
        
        # Create subtitle
        subtitle = f"High Severity Vulnerabilities ({len(high_vulns)} total)"
        if len(high_chunks) > 1:
            start_idx = chunk_idx * max_rows + 1
            end_idx = min((chunk_idx + 1) * max_rows, len(high_vulns))
            subtitle += f" - Items {start_idx}-{end_idx}"
        
        SlideUtils.create_subtitle(slide, layout['table_left'], Inches(0.8), layout['max_table_width'], subtitle)
        
        # Calculate totals for this chunk
        chunk_totals = SlideUtils.calculate_column_totals(chunk, 5, "Page Total")
        
        # Create table
        data_with_totals = chunk + [chunk_totals]
        table = SlideUtils.create_table_with_headers(slide, len(data_with_totals) + 1, 5,
                                                   layout['table_left'], Inches(1.2), 
                                                   layout['max_table_width'], Inches(4.8))
        
        column_widths = [Inches(6.95), Inches(1.39), Inches(1.11), Inches(1.11), Inches(1.76)]
        SlideUtils.set_table_column_widths(table, column_widths)
        SlideUtils.set_table_row_heights(table, Inches(0.35), Inches(0.32))
        SlideUtils.format_header_row(table, slide3_data["table2"]["columns"])
        SlideUtils.populate_table_data(table, data_with_totals)
        
        # Add footer with navigation info
        if len(high_chunks) > 1:
            footer_text = f"High Vulnerabilities - Page {chunk_idx + 1} of {len(high_chunks)}"
            SlideUtils.create_footnote(slide, layout['table_left'], Inches(6.2), 
                                     layout['max_table_width'], footer_text, font_size=10)
        
        slides_created.append(slide)
    
    return slides_created


def _create_vulnerability_summary_slide(prs, slide3_data, critical_vulns, high_vulns):
    """Create a summary overview slide when multiple detail slides exist"""
    slide_layout = prs.slide_layouts[6]
    slide = prs.slides.add_slide(slide_layout)
    
    # Create title
    SlideUtils.create_title_bar(slide, prs, f"{slide3_data['title']} - Executive Summary")
    
    # Get layout parameters
    layout = SlideUtils.get_standard_layout_params(prs)
    
    # Create summary statistics
    critical_total = SlideUtils.calculate_column_totals(critical_vulns, 5, "Total")
    high_total = SlideUtils.calculate_column_totals(high_vulns, 5, "Total")
    
    # Summary table
    summary_data = [
        ["Vulnerability Category", "Count", "Critical", "High", "Medium", "Total CVEs"],
        ["Critical Severity", str(len(critical_vulns)), str(critical_total[1]), str(critical_total[2]), str(critical_total[3]), str(critical_total[4])],
        ["High Severity", str(len(high_vulns)), str(high_total[1]), str(high_total[2]), str(high_total[3]), str(high_total[4])],
        ["Combined Total", str(len(critical_vulns) + len(high_vulns)), str(critical_total[1] + high_total[1]), str(critical_total[2] + high_total[2]), str(critical_total[3] + high_total[3]), str(critical_total[4] + high_total[4])]
    ]
    
    # Create summary table
    table = SlideUtils.create_table_with_headers(slide, 4, 6, layout['table_left'], Inches(1.2), 
                                               layout['max_table_width'], Inches(1.6))
    
    column_widths = [Inches(3.5), Inches(1.5), Inches(1.39), Inches(1.11), Inches(1.11), Inches(1.76)]
    SlideUtils.set_table_column_widths(table, column_widths)
    SlideUtils.set_table_row_heights(table, Inches(0.35), Inches(0.4))
    SlideUtils.format_header_row(table, summary_data[0])
    SlideUtils.populate_table_data(table, summary_data[1:])
    
    # Add risk impact information
    if slide3_data.get("footnote"):
        _create_risk_impact_table(slide, slide3_data, layout, top_position=Inches(3.2))
    
    # Add key findings text box
    findings_text = f"""Key Findings:
• {len(critical_vulns)} Critical vulnerabilities requiring immediate attention
• {len(high_vulns)} High severity vulnerabilities for priority remediation
• Detailed breakdown available in following slides
• Immediate action required for business continuity"""
    
    findings_box = slide.shapes.add_textbox(layout['table_left'], Inches(4.5), 
                                          layout['max_table_width'], Inches(1.5))
    findings_tf = findings_box.text_frame
    findings_tf.text = findings_text
    for paragraph in findings_tf.paragraphs:
        paragraph.font.size = Pt(12)
        paragraph.font.color.rgb = RGBColor(0, 0, 0)
    
    return slide


def _create_risk_impact_table(slide, slide3_data, layout, top_position=Inches(6.4)):
    """Create risk and impact table with flexible positioning"""
    if not slide3_data.get("footnote"):
        return
        
    table_data = {
        "columns": ["Risk", "Impact"],
        "rows": [[slide3_data["footnote"]["Risk"], slide3_data["footnote"]["Impact"]]]
    }
    
    table = SlideUtils.create_table_with_headers(slide, 2, 2, layout['table_left'], top_position, 
                                               layout['max_table_width'], Inches(0.8))
    SlideUtils.set_table_column_widths(table, [Inches(6.165), Inches(6.165)])
    SlideUtils.set_table_row_heights(table, Inches(0.35), Inches(0.4))
    SlideUtils.format_header_row(table, table_data["columns"])
    SlideUtils.populate_table_data(table, table_data["rows"])


def _split_rows_for_slides(rows, max_rows_per_slide):
    """Split list of rows into smaller chunks for pagination"""
    for i in range(0, len(rows), max_rows_per_slide):
        yield rows[i:i + max_rows_per_slide]


def _print_slide3_results(start_time, critical_vulns, high_vulns, slides_created):
    """Print enhanced slide 3 results with pagination info"""
    runtime = time.time() - start_time
    print(f"Slide 3 series created successfully!")
    print(f"Critical vulnerabilities: {len(critical_vulns)} items")
    print(f"High severity vulnerabilities: {len(high_vulns)} items") 
    print(f"Total slides created: {slides_created}")
    
    if len(critical_vulns) > 12:
        print(f"✓ Critical vulnerabilities split across multiple slides for readability")
    if len(high_vulns) > 12:
        print(f"✓ High vulnerabilities split across multiple slides for readability")
        
    print(f"Runtime: {runtime:.4f} seconds")


# Update your main slide generation to handle multiple slides returned
def handle_slide3_creation(prs, slide3_data):
    """Handle slide 3 creation which might return multiple slides"""
    result = create_slide3(prs, slide3_data)
    
    if isinstance(result, tuple):
        slides_created, runtime = result
        return slides_created, runtime
    else:
        # Fallback for single slide
        return [result], 0

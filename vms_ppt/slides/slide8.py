import time
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from .slide_utils import SlideUtils


def create_slide8(prs: Presentation, slide8_data):
    """Create slide(s) for Stage 1 Software Update/Uninstallation with pagination"""
    start_time = time.time()
    
    # Check if we need to split into multiple slides
    software_data = slide8_data.get("table", {}).get("rows", [])
    
    slides_created = []
    
    # Define max rows per slide (accounting for table headers and layout)
    MAX_ROWS_PER_SLIDE = 10
    
    # Filter out existing total rows and create pagination
    filtered_rows = [row for row in software_data if "Total" not in str(row[0])]
    
    # Create paginated slides for software data
    software_slides = _create_software_slides(prs, slide8_data, filtered_rows, MAX_ROWS_PER_SLIDE)
    slides_created.extend(software_slides)
    
    # Create summary slide if we have multiple slides
    if len(slides_created) > 1:
        summary_slide = _create_software_summary_slide(prs, slide8_data, filtered_rows)
        slides_created.insert(0, summary_slide)
    
    # Print results
    _print_slide8_results(start_time, filtered_rows, len(slides_created))
    
    return slides_created, time.time() - start_time


def _create_software_slides(prs, slide8_data, software_data, max_rows):
    """Create one or more slides for software update/uninstallation data"""
    if not software_data or len(software_data) == 0:
        return []
    
    slides_created = []
    software_chunks = list(_split_rows_for_slides(software_data, max_rows))
    
    for chunk_idx, chunk in enumerate(software_chunks):
        slide_layout = prs.slide_layouts[6]
        slide = prs.slides.add_slide(slide_layout)
        
        # Create title with page number if multiple slides
        title = slide8_data["title"]
        if len(software_chunks) > 1:
            title += f" (Page {chunk_idx + 1} of {len(software_chunks)})"
        
        SlideUtils.create_title_bar(slide, prs, title)
        
        # Get layout parameters
        layout = SlideUtils.get_standard_layout_params(prs)
        
        # Create subtitle with item range
        subtitle = f"Software Update/Uninstallation Details ({len(software_data)} total items)"
        if len(software_chunks) > 1:
            start_idx = chunk_idx * max_rows + 1
            end_idx = min((chunk_idx + 1) * max_rows, len(software_data))
            subtitle += f" - Items {start_idx}-{end_idx}"
        
        SlideUtils.create_subtitle(slide, layout['table_left'], Inches(0.8), 
                                 layout['max_table_width'], subtitle)
        
        # Calculate totals for this chunk
        chunk_totals = SlideUtils.calculate_column_totals(chunk, 
                                                        len(slide8_data["table"]["columns"]), 
                                                        "Page Total")
        
        # Create table
        data_with_totals = chunk + [chunk_totals]
        table = SlideUtils.create_table_with_headers(slide, len(data_with_totals) + 1, 
                                                   len(slide8_data["table"]["columns"]),
                                                   layout['table_left'], Inches(1.2), 
                                                   layout['max_table_width'], Inches(4.8))
        
        # Set column widths for software table
        column_widths = [Inches(3.5), Inches(1.5), Inches(1.5), Inches(1.5), Inches(1.5), Inches(2.0)]
        SlideUtils.set_table_column_widths(table, column_widths)
        SlideUtils.set_table_row_heights(table, Inches(0.35), Inches(0.3))
        SlideUtils.format_header_row(table, slide8_data["table"]["columns"])
        SlideUtils.populate_table_data(table, data_with_totals)
        
        # Add footer with navigation info
        if len(software_chunks) > 1:
            footer_text = f"Software Update Details - Page {chunk_idx + 1} of {len(software_chunks)}"
            SlideUtils.create_footnote(slide, layout['table_left'], Inches(6.2), 
                                     layout['max_table_width'], footer_text, font_size=10)
        
        slides_created.append(slide)
    
    return slides_created


def _create_software_summary_slide(prs, slide8_data, software_data):
    """Create a summary overview slide when multiple detail slides exist"""
    slide_layout = prs.slide_layouts[6]
    slide = prs.slides.add_slide(slide_layout)
    
    # Create title
    SlideUtils.create_title_bar(slide, prs, f"{slide8_data['title']} - Executive Summary")
    
    # Get layout parameters
    layout = SlideUtils.get_standard_layout_params(prs)
    
    # Calculate overall totals
    overall_totals = SlideUtils.calculate_column_totals(software_data, 
                                                      len(slide8_data["table"]["columns"]), 
                                                      "Grand Total")
    
    # Create summary statistics table
    summary_data = [
        ["Metric", "Value"],
        ["Total Software Applications", str(len(software_data))],
        ["Critical Priority Updates", str(overall_totals[1])],
        ["High Priority Updates", str(overall_totals[2])],
        ["Immediate Action Required", str(overall_totals[3])],
        ["Medium Priority Updates", str(overall_totals[4])],
        ["Total Updates Required", str(overall_totals[5])]
    ]
    
    # Create summary table
    table = SlideUtils.create_table_with_headers(slide, len(summary_data), 2, 
                                               layout['table_left'], Inches(1.2), 
                                               Inches(8.0), Inches(2.5))
    
    column_widths = [Inches(4.0), Inches(4.0)]
    SlideUtils.set_table_column_widths(table, column_widths)
    SlideUtils.set_table_row_heights(table, Inches(0.35), Inches(0.35))
    SlideUtils.format_header_row(table, summary_data[0])
    SlideUtils.populate_table_data(table, summary_data[1:])
    
    # Add key findings text box
    findings_text = f"""Key Findings - Stage 1 Software Updates:
• {len(software_data)} software applications require updates or uninstallation
• {overall_totals[3]} applications require immediate action
• {overall_totals[1]} critical priority software updates identified
• {overall_totals[5]} total software remediation actions needed
• Detailed application-specific breakdown available in following slides"""
    
    findings_box = slide.shapes.add_textbox(layout['table_left'], Inches(4.0), 
                                          layout['max_table_width'], Inches(2.0))
    findings_tf = findings_box.text_frame
    findings_tf.text = findings_text
    for paragraph in findings_tf.paragraphs:
        paragraph.font.size = Pt(12)
        paragraph.font.color.rgb = RGBColor(0, 0, 0)
    
    return slide


def _split_rows_for_slides(rows, max_rows_per_slide):
    """Split list of rows into smaller chunks for pagination"""
    for i in range(0, len(rows), max_rows_per_slide):
        yield rows[i:i + max_rows_per_slide]


def _print_slide8_results(start_time, software_data, slides_created):
    """Print enhanced slide 8 results with pagination info"""
    runtime = time.time() - start_time
    print(f"Slide 8 series created successfully!")
    print(f"Software applications: {len(software_data)} items")
    print(f"Total slides created: {slides_created}")
    
    if len(software_data) > 10:
        print(f"✓ Software update data split across multiple slides for readability")
        
    print(f"Runtime: {runtime:.4f} seconds")

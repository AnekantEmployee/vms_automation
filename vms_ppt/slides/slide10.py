import time
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import MSO_ANCHOR
from config_colors import COLORS, FONT_SIZES

def create_slide10(prs: Presentation, slide10_data):
    start_time = time.time()

    # Calculate grand totals dynamically
    total_critical = 0
    total_medium = 0
    for row in slide10_data["table"]["rows"]:
        # Extract Critical column (index 1)
        critical_value = row[1].strip() if row[1] else "0"
        # Extract Medium column (index 2)
        medium_value = row[2].strip() if row[2] else "0"
        # Add to totals if numeric
        if critical_value.isdigit():
            total_critical += int(critical_value)
        if medium_value.isdigit():
            total_medium += int(medium_value)

    # Calculate grand total
    grand_total = total_critical + total_medium

    # Create calculated totals row
    calculated_totals = ["Grand Total", str(total_critical), str(total_medium), str(grand_total)]

    slide_layout = prs.slide_layouts[6] # Blank layout
    slide = prs.slides.add_slide(slide_layout)

    # Create blue title bar
    left = Inches(0)
    top = Inches(0)
    width = prs.slide_width
    height = Inches(0.6)
    shape = slide.shapes.add_shape(1, left, top, width, height) # Rectangle
    shape.fill.solid()
    shape.fill.fore_color.rgb = RGBColor(*COLORS["blue"])
    shape.line.color.rgb = RGBColor(*COLORS["blue"])

    # Add title text box
    title_box = slide.shapes.add_textbox(left, top, width, height)
    tf = title_box.text_frame
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = tf.paragraphs[0]
    p.text = slide10_data["title"]
    p.font.bold = True
    p.font.size = Pt(FONT_SIZES["title"])
    p.font.color.rgb = RGBColor(*COLORS["white"])
    p.alignment = 1 # Center

    # Add table (REMOVED hardcoded totals from data, will add calculated totals)
    table_left = Inches(0.5)
    table_top = Inches(1.0)
    table_width = prs.slide_width - Inches(1)

    # Table rows: header + data rows + calculated totals row
    data_rows = len(slide10_data["table"]["rows"])
    total_rows = data_rows + 2 # +1 for header, +1 for calculated totals
    cols = len(slide10_data["table"]["columns"])
    
    # Calculate appropriate table height based on number of rows
    table_height = Inches(0.4 + (total_rows * 0.35))  # Header + rows
    table = slide.shapes.add_table(total_rows, cols, table_left, table_top, table_width, table_height).table

    # Set column widths
    table.columns[0].width = Inches(7) # OS Hardening/Configuration column
    table.columns[1].width = Inches(1.5) # Critical column
    table.columns[2].width = Inches(1.5) # Medium column
    table.columns[3].width = Inches(1.5) # Grand Total column

    # Set row heights for all rows
    table.rows[0].height = Inches(0.4)  # Header row
    for i in range(1, total_rows):
        table.rows[i].height = Inches(0.35)  # Data and total rows

    # Header row with blue background
    header_row = table.rows[0]
    for i, col_name in enumerate(slide10_data["table"]["columns"]):
        cell = header_row.cells[i]
        cell.text = col_name
        cell.fill.solid()
        cell.fill.fore_color.rgb = RGBColor(*COLORS["blue"])
        # Set text formatting for header
        paragraph = cell.text_frame.paragraphs[0]
        paragraph.font.bold = True
        paragraph.font.size = Pt(FONT_SIZES["table_header"])
        paragraph.font.color.rgb = RGBColor(*COLORS["white"])
        paragraph.alignment = 1 # Center alignment

    # Data rows (EXCLUDING any hardcoded totals row)
    for row_idx, row_data in enumerate(slide10_data["table"]["rows"]):
        # Skip if this is a totals row (contains "Grand Total")
        if "Grand Total" in row_data[0]:
            continue

        table_row = table.rows[row_idx + 1] # +1 to skip header row
        for col_idx, cell_data in enumerate(row_data):
            cell = table_row.cells[col_idx]
            cell.text = cell_data
            # Set text formatting for data cells
            paragraph = cell.text_frame.paragraphs[0]
            paragraph.font.size = Pt(FONT_SIZES["table_data"])
            paragraph.font.color.rgb = RGBColor(*COLORS["black"])
            # Center align numbers
            if col_idx > 0: # Number columns
                paragraph.alignment = 1 # Center alignment
            # Alternate row coloring
            if row_idx % 2 == 0:
                cell.fill.solid()
                cell.fill.fore_color.rgb = RGBColor(*COLORS["very_light_gray"])

    # Add CALCULATED totals row with blue background
    totals_row_index = total_rows - 1 # Last row
    totals_row = table.rows[totals_row_index]
    for i, total_data in enumerate(calculated_totals):
        cell = totals_row.cells[i]
        cell.text = total_data
        cell.fill.solid()
        cell.fill.fore_color.rgb = RGBColor(*COLORS["blue"])
        # Set text formatting for totals
        paragraph = cell.text_frame.paragraphs[0]
        paragraph.font.bold = True
        paragraph.font.size = Pt(FONT_SIZES["table_totals"])
        paragraph.font.color.rgb = RGBColor(*COLORS["white"])
        if i > 0: # Number columns
            paragraph.alignment = 1 # Center alignment

    end_time = time.time()
    runtime = end_time - start_time
    print(f"Slide 10 created successfully!")
    print(f"Calculated Totals - Critical: {total_critical}, Medium: {total_medium}, Grand Total: {grand_total}")
    print(f"Runtime: {runtime:.4f} seconds")
    return runtime

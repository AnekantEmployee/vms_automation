from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import MSO_ANCHOR
import time
from config_colors import COLORS, FONT_SIZES

def create_slide5(prs: Presentation, slide5_data):
    start_time = time.time()
    
    # Calculate column totals dynamically
    columns_count = len(slide5_data["table"]["columns"])
    totals = ["Grand Total"]  # First cell for row label
    
    # Initialize totals for numeric columns (Critical, High, Immediate)
    for _ in range(1, columns_count - 1):  # Skip Operating System and Grand Total columns
        totals.append(0)
    
    # Sum each numeric column
    for row in slide5_data["table"]["rows"]:
        for col_idx in range(1, columns_count - 1):  # Skip Operating System and Grand Total columns
            value = row[col_idx].strip() if row[col_idx] else "0"
            if value.isdigit():
                totals[col_idx] += int(value)
    
    # Calculate grand total from component totals
    grand_total = sum(totals[1:])
    totals.append(grand_total)
    
    slide_layout = prs.slide_layouts[6]  # Blank layout
    slide = prs.slides.add_slide(slide_layout)

    # Create blue title bar
    left = Inches(0)
    top = Inches(0)
    width = prs.slide_width
    height = Inches(0.6)

    shape = slide.shapes.add_shape(1, left, top, width, height)
    shape.fill.solid()
    shape.fill.fore_color.rgb = RGBColor(*COLORS["blue"])
    shape.line.color.rgb = RGBColor(*COLORS["blue"])

    # Add title text box
    title_box = slide.shapes.add_textbox(left, top, width, height)
    tf = title_box.text_frame
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE

    p = tf.paragraphs[0]
    p.text = slide5_data["title"]
    p.font.bold = True
    p.font.size = Pt(FONT_SIZES["title"])
    p.font.color.rgb = RGBColor(*COLORS["white"])
    p.alignment = 1  # Center

    # Add subtitle
    subtitle_left = Inches(0.5)
    subtitle_top = Inches(0.8)
    subtitle_width = prs.slide_width - Inches(1.0)
    
    subtitle_box = slide.shapes.add_textbox(subtitle_left, subtitle_top, subtitle_width, Inches(0.3))
    subtitle_tf = subtitle_box.text_frame
    subtitle_p = subtitle_tf.paragraphs[0]
    subtitle_p.text = slide5_data["subtitle"]
    subtitle_p.font.bold = True
    subtitle_p.font.size = Pt(16)
    subtitle_p.font.color.rgb = RGBColor(*COLORS["black"])
    subtitle_p.alignment = 1  # Center

    # Calculate table dimensions properly to fit within slide
    max_table_width = prs.slide_width - Inches(1.0)  # 1" total margin
    table_left = Inches(0.5)  # 0.5" left margin
    table_top = Inches(1.2)
    
    # Table rows: header + data rows + calculated totals row
    data_rows = len(slide5_data["table"]["rows"])
    total_rows = data_rows + 2  # +1 for header, +1 for calculated totals
    cols = len(slide5_data["table"]["columns"])
    
    table = slide.shapes.add_table(total_rows, cols, table_left, table_top, max_table_width, Inches(5.5)).table
    
    # Set column widths that properly fit within slide width
    table.columns[0].width = Inches(6.5)   # Operating System column
    table.columns[1].width = Inches(1.5)   # Critical column
    table.columns[2].width = Inches(1.5)   # High column
    table.columns[3].width = Inches(1.5)   # Immediate column
    table.columns[4].width = Inches(1.3)   # Grand Total column

    # Header row with blue background
    header_row = table.rows[0]
    for i, col_name in enumerate(slide5_data["table"]["columns"]):
        cell = header_row.cells[i]
        cell.text = col_name
        cell.fill.solid()
        cell.fill.fore_color.rgb = RGBColor(*COLORS["blue"])
        
        # Set text formatting for header
        paragraph = cell.text_frame.paragraphs[0]
        paragraph.font.bold = True
        paragraph.font.size = Pt(FONT_SIZES["table_header"])
        paragraph.font.color.rgb = RGBColor(*COLORS["white"])
        paragraph.alignment = 1  # Center alignment

    # Data rows (excluding any existing totals)
    filtered_rows = [row for row in slide5_data["table"]["rows"] if "Total" not in row[0]]
    
    for row_idx, row_data in enumerate(filtered_rows):
        table_row = table.rows[row_idx + 1]  # +1 to skip header row
        for col_idx, cell_data in enumerate(row_data):
            cell = table_row.cells[col_idx]
            cell.text = str(cell_data) if cell_data else ""
            
            # Set text formatting for data cells
            paragraph = cell.text_frame.paragraphs[0]
            paragraph.font.size = Pt(FONT_SIZES["table_data"])
            paragraph.font.color.rgb = RGBColor(*COLORS["black"])
            
            # Center align numbers
            if col_idx > 0:  # Number columns
                paragraph.alignment = 1  # Center alignment
            
            # Alternate row coloring
            if row_idx % 2 == 0:
                cell.fill.solid()
                cell.fill.fore_color.rgb = RGBColor(*COLORS["very_light_gray"])

    # Add CALCULATED totals row with blue background
    totals_row_index = len(filtered_rows) + 1  # After data rows + header
    totals_row = table.rows[totals_row_index]
    
    for i, total_data in enumerate(totals):
        cell = totals_row.cells[i]
        cell.text = str(total_data)
        cell.fill.solid()
        cell.fill.fore_color.rgb = RGBColor(*COLORS["blue"])
        
        # Set text formatting for totals
        paragraph = cell.text_frame.paragraphs[0]
        paragraph.font.bold = True
        paragraph.font.size = Pt(FONT_SIZES["table_totals"])
        paragraph.font.color.rgb = RGBColor(*COLORS["white"])
        
        if i > 0:  # Number columns
            paragraph.alignment = 1  # Center alignment
    
    end_time = time.time()
    runtime = end_time - start_time
    
    print(f"Slide 5 created successfully!")
    print(f"Calculated Totals - Critical: {totals[1]}, High: {totals[2]}, Immediate: {totals[3]}, Grand Total: {totals[4]}")
    print(f"Runtime: {runtime:.4f} seconds")
    
    return runtime

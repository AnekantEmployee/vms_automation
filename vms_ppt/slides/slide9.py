import time
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import MSO_ANCHOR
from config_colors import COLORS, FONT_SIZES

def create_slide9(prs: Presentation, slide9_data):
    start_time = time.time()
    
    # Calculate Part 1 Total dynamically
    part1_total = 0
    for row in slide9_data["tables"][0]["rows"]:
        if "Total" not in row[0]:  # Skip any existing total rows
            immediate_value = row[1].strip() if row[1] else "0"
            if immediate_value.isdigit():
                part1_total += int(immediate_value)
    
    # Calculate Part 2 Total dynamically
    part2_total = 0
    for row in slide9_data["tables"][1]["rows"]:
        if "Total" not in row[0]:  # Skip any existing total rows
            immediate_value = row[1].strip() if row[1] else "0"
            if immediate_value.isdigit():
                part2_total += int(immediate_value)
    
    # Calculate Grand Total
    grand_total = part1_total + part2_total
    
    # Create calculated totals
    part1_total_row = ["Part 1 Total", str(part1_total)]
    part2_total_row = ["Part 2 Total", str(part2_total)]
    
    slide_layout = prs.slide_layouts[6]  # Blank layout
    slide = prs.slides.add_slide(slide_layout)

    # Create blue title bar
    left = Inches(0)
    top = Inches(0)
    width = prs.slide_width
    height = Inches(0.6)

    shape = slide.shapes.add_shape(1, left, top, width, height)  # Rectangle
    shape.fill.solid()
    shape.fill.fore_color.rgb = RGBColor(*COLORS["blue"])
    shape.line.color.rgb = RGBColor(*COLORS["blue"])

    # Add title text box
    title_box = slide.shapes.add_textbox(left, top, width, height)
    tf = title_box.text_frame
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE

    p = tf.paragraphs[0]
    p.text = slide9_data["title"]
    p.font.bold = True
    p.font.size = Pt(FONT_SIZES["title"])
    p.font.color.rgb = RGBColor(*COLORS["white"])
    p.alignment = 1  # Center

    # Layout for two tables side by side
    mid_point = prs.slide_width // 2
    left_margin = Inches(0.3)
    table_width = mid_point - Inches(0.6)  # Adjust for margins
    
    # Helper function to set full blue fill for header and total rows
    def set_row_blue_full_fill(table, row_idx):
        """Set entire row to blue background with white bold text"""
        for cell in table.rows[row_idx].cells:
            cell.fill.solid()
            cell.fill.fore_color.rgb = RGBColor(*COLORS["blue"])
            p = cell.text_frame.paragraphs[0]
            p.font.bold = True
            p.font.color.rgb = RGBColor(*COLORS["white"])
            # FIXED: Use same font size as content for headers
            p.font.size = Pt(FONT_SIZES["table_data"])
            if cell.text.isdigit():  # Center align numbers
                p.alignment = 1
    
    # Add left table (Part 1) with calculated total
    t1_data = slide9_data["tables"][0]["rows"]
    t1_filtered = [row for row in t1_data if "Total" not in row[0]]
    t1_filtered.append(part1_total_row)  # Add calculated total
    
    rows_t1 = len(t1_filtered) + 1  # +1 for header
    cols_t1 = 2
    
    table1 = slide.shapes.add_table(rows_t1, cols_t1, left_margin, Inches(1), table_width, Inches(4.5)).table
    
    # Set column widths - CONSISTENT ACROSS ALL TABLES
    table1.columns[0].width = Inches(3.5)
    table1.columns[1].width = Inches(1.5)

    # Header for table 1
    header_cells = ["EOL", "Immediate"]
    for i, col_name in enumerate(header_cells):
        cell = table1.cell(0, i)
        cell.text = col_name

    # Data rows for table 1
    for row_idx, row_data in enumerate(t1_filtered):
        for col_idx, cell_text in enumerate(row_data):
            cell = table1.cell(row_idx + 1, col_idx)
            cell.text = cell_text
            p = cell.text_frame.paragraphs[0]
            p.font.size = Pt(FONT_SIZES["table_data"])
            p.font.color.rgb = RGBColor(*COLORS["black"])
            
            # Center align numbers
            if col_idx == 1:
                p.alignment = 1
            
            # Alternate row coloring for data rows (NOT for total row)
            if "Total" not in cell_text and row_idx % 2 == 0:
                cell.fill.solid()
                cell.fill.fore_color.rgb = RGBColor(*COLORS["very_light_gray"])

    # APPLY FULL BLUE FILL TO HEADER AND TOTAL ROWS OF TABLE 1
    set_row_blue_full_fill(table1, 0)  # Header row
    set_row_blue_full_fill(table1, len(table1.rows) - 1)  # Total row

    # Add right table (Part 2) with calculated total
    t2_data = slide9_data["tables"][1]["rows"]
    t2_filtered = [row for row in t2_data if "Total" not in row[0]]
    t2_filtered.append(part2_total_row)  # Add calculated total
    
    rows_t2 = len(t2_filtered) + 1  # +1 for header
    cols_t2 = 2
    
    table2 = slide.shapes.add_table(rows_t2, cols_t2, mid_point + Inches(0.3), Inches(1), table_width, Inches(4.5)).table
    
    # Set column widths - CONSISTENT ACROSS ALL TABLES
    table2.columns[0].width = Inches(3.5)
    table2.columns[1].width = Inches(1.5)

    # Header for table 2
    for i, col_name in enumerate(header_cells):
        cell = table2.cell(0, i)
        cell.text = col_name

    # Data rows for table 2
    for row_idx, row_data in enumerate(t2_filtered):
        for col_idx, cell_text in enumerate(row_data):
            cell = table2.cell(row_idx + 1, col_idx)
            cell.text = cell_text
            p = cell.text_frame.paragraphs[0]
            p.font.size = Pt(FONT_SIZES["table_data"])
            p.font.color.rgb = RGBColor(*COLORS["black"])
            
            # Center align numbers
            if col_idx == 1:
                p.alignment = 1
            
            # Alternate row coloring for data rows (NOT for total row)
            if "Total" not in cell_text and row_idx % 2 == 0:
                cell.fill.solid()
                cell.fill.fore_color.rgb = RGBColor(*COLORS["very_light_gray"])

    # APPLY FULL BLUE FILL TO HEADER AND TOTAL ROWS OF TABLE 2
    set_row_blue_full_fill(table2, 0)  # Header row
    set_row_blue_full_fill(table2, len(table2.rows) - 1)  # Total row

    # Add summary table with calculated totals
    summary_data = [
        ["Part 1 Total", str(part1_total)],
        ["Part 2 Total", str(part2_total)],
        ["Grand Total", str(grand_total)]
    ]
    
    rows_sum = len(summary_data) + 1  # +1 for header
    cols_sum = 2

    sum_table = slide.shapes.add_table(rows_sum, cols_sum, left_margin, Inches(5.8), table_width, Inches(1.2)).table

    # Set column widths for summary table - SAME AS OTHER TABLES
    sum_table.columns[0].width = Inches(3.5)
    sum_table.columns[1].width = Inches(1.5)

    # Header for summary table
    for i, col_name in enumerate(header_cells):
        cell = sum_table.cell(0, i)
        cell.text = col_name

    # Data rows for summary table
    for row_idx, row_data in enumerate(summary_data):
        for col_idx, cell_text in enumerate(row_data):
            cell = sum_table.cell(row_idx + 1, col_idx)
            cell.text = cell_text

    # FIXED: Apply proper formatting to summary table rows
    # UPDATED: Apply proper formatting to summary table rows
    # Row 0 (header) - Blue
    for cell in sum_table.rows[0].cells:
        cell.fill.solid()
        cell.fill.fore_color.rgb = RGBColor(*COLORS["blue"])
        p = cell.text_frame.paragraphs[0]
        p.font.bold = True
        p.font.size = Pt(FONT_SIZES["table_data"])
        p.font.color.rgb = RGBColor(*COLORS["white"])
        p.space_before = Pt(0)
        p.space_after = Pt(0)
        if cell.text.isdigit():
            p.alignment = 1

    # Row 1 (Part 1 Total) - Light Grey
    for cell in sum_table.rows[1].cells:
        cell.fill.solid()
        cell.fill.fore_color.rgb = RGBColor(*COLORS["very_light_gray"])
        p = cell.text_frame.paragraphs[0]
        p.font.bold = False
        p.font.size = Pt(FONT_SIZES["table_data"])
        p.font.color.rgb = RGBColor(*COLORS["black"])
        p.space_before = Pt(0)
        p.space_after = Pt(0)
        if cell.text.isdigit():
            p.alignment = 1

    # Row 2 (Part 2 Total) - Light Blue
    for cell in sum_table.rows[2].cells:
        cell.fill.solid()
        cell.fill.fore_color.rgb = RGBColor(*COLORS["very_light_gray"])
        p = cell.text_frame.paragraphs[0]
        p.font.bold = False
        p.font.size = Pt(FONT_SIZES["table_data"])
        p.font.color.rgb = RGBColor(*COLORS["black"])
        p.space_before = Pt(0)
        p.space_after = Pt(0)
        if cell.text.isdigit():
            p.alignment = 1

    # Row 3 (Grand Total) - Blue
    for cell in sum_table.rows[3].cells:
        cell.fill.solid()
        cell.fill.fore_color.rgb = RGBColor(*COLORS["blue"])
        p = cell.text_frame.paragraphs[0]
        p.font.bold = True
        p.font.size = Pt(FONT_SIZES["table_data"])
        p.font.color.rgb = RGBColor(*COLORS["white"])
        p.space_before = Pt(0)
        p.space_after = Pt(0)
        if cell.text.isdigit():
            p.alignment = 1
            
            
    end_time = time.time()
    runtime = end_time - start_time
    
    print(f"Slide 9 created successfully!")
    print(f"Calculated Totals - Part 1: {part1_total}, Part 2: {part2_total}, Grand Total: {grand_total}")
    print(f"Runtime: {runtime:.4f} seconds")
    
    return runtime

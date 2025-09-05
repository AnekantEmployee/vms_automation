from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import MSO_ANCHOR
import time
from config_colors import COLORS, FONT_SIZES

def create_slide4(prs: Presentation, slide4_data):
    start_time = time.time()

    # Calculate totals for Table 1 (Software Update/Uninstallation)
    table1_totals = ["Grand Total", 0, 0, 0, 0, 0]
    for row in slide4_data["table1"]["rows"]:
        for col_idx in range(1, 6): # Skip software name column
            value = row[col_idx].strip() if row[col_idx] else "0"
            if value.isdigit():
                table1_totals[col_idx] += int(value)
    # Calculate grand total for table 1
    table1_totals[5] = sum(table1_totals[1:5])

    # Calculate totals for Table 2 (OS Hardening/Configuration)
    table2_totals = ["Grand Total", 0, 0, 0]
    for row in slide4_data["table2"]["rows"]:
        for col_idx in range(1, 4): # Skip vulnerability name column
            value = row[col_idx].strip() if row[col_idx] else "0"
            if value.isdigit():
                table2_totals[col_idx] += int(value)
    # Calculate grand total for table 2
    table2_totals[3] = sum(table2_totals[1:3])

    slide_layout = prs.slide_layouts[6] # Blank layout
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
    p.text = slide4_data["title"]
    p.font.bold = True
    p.font.size = Pt(FONT_SIZES["title"])
    p.font.color.rgb = RGBColor(*COLORS["white"])
    p.alignment = 1

    # Calculate table dimensions to fit properly within slide
    max_table_width = prs.slide_width - Inches(1.0) # 1" total margin
    table_left = Inches(0.5) # 0.5" left margin

    # Table 1 - Software Update/Uninstallation
    table1_top = Inches(0.8)

    # Add Table 1 subtitle
    subtitle1_box = slide.shapes.add_textbox(table_left, table1_top, max_table_width, Inches(0.3))
    subtitle1_tf = subtitle1_box.text_frame
    subtitle1_p = subtitle1_tf.paragraphs[0]
    subtitle1_p.text = slide4_data["subtitle1"]
    subtitle1_p.font.bold = True
    subtitle1_p.font.size = Pt(14)
    subtitle1_p.font.color.rgb = RGBColor(*COLORS["black"])
    subtitle1_p.alignment = 1

    # Create Table 1
    table1_data_with_totals = slide4_data["table1"]["rows"] + [table1_totals]
    table1_rows = len(table1_data_with_totals) + 1 # +1 for header
    table1_cols = len(slide4_data["table1"]["columns"])
    
    # Calculate appropriate table height based on number of rows
    table1_height = Inches(0.4 + (table1_rows * 0.3))  # Header + rows
    table1 = slide.shapes.add_table(table1_rows, table1_cols, table_left, Inches(1.2), max_table_width, table1_height).table

    # Set Table 1 column widths
    table1.columns[0].width = Inches(3.5) # Software
    table1.columns[1].width = Inches(1.5) # Critical
    table1.columns[2].width = Inches(1.5) # High
    table1.columns[3].width = Inches(1.5) # Immediate
    table1.columns[4].width = Inches(1.5) # Medium
    table1.columns[5].width = Inches(2.8) # Grand Total

    # Set row heights for table 1
    table1.rows[0].height = Inches(0.4)  # Header row
    for i in range(1, table1_rows):
        table1.rows[i].height = Inches(0.3)  # Data rows

    # Table 1 header row
    for i, col_name in enumerate(slide4_data["table1"]["columns"]):
        cell = table1.cell(0, i)
        cell.text = col_name
        cell.fill.solid()
        cell.fill.fore_color.rgb = RGBColor(*COLORS["blue"])
        paragraph = cell.text_frame.paragraphs[0]
        paragraph.font.bold = True
        paragraph.font.size = Pt(FONT_SIZES["table_header"])
        paragraph.font.color.rgb = RGBColor(*COLORS["white"])
        paragraph.alignment = 1

    # Table 1 data rows
    for row_idx, row_data in enumerate(table1_data_with_totals):
        for col_idx, cell_data in enumerate(row_data):
            cell = table1.cell(row_idx + 1, col_idx)
            cell.text = str(cell_data) if cell_data else ""
            paragraph = cell.text_frame.paragraphs[0]
            paragraph.font.size = Pt(FONT_SIZES["table_data"])
            paragraph.font.color.rgb = RGBColor(*COLORS["black"])
            # Center align numbers
            if col_idx > 0:
                paragraph.alignment = 1
            # Blue background for Grand Total row
            if row_data[0] == "Grand Total":
                cell.fill.solid()
                cell.fill.fore_color.rgb = RGBColor(*COLORS["blue"])
                paragraph.font.bold = True
                paragraph.font.color.rgb = RGBColor(*COLORS["white"])
            # Alternate row coloring for data rows
            elif row_idx % 2 == 0:
                cell.fill.solid()
                cell.fill.fore_color.rgb = RGBColor(*COLORS["very_light_gray"])

    # Table 2 - OS Hardening/Configuration
    table2_top = Inches(1.2) + table1_height + Inches(0.4)  # After table1 + gap

    # Add Table 2 subtitle
    subtitle2_box = slide.shapes.add_textbox(table_left, table2_top, max_table_width, Inches(0.3))
    subtitle2_tf = subtitle2_box.text_frame
    subtitle2_p = subtitle2_tf.paragraphs[0]
    subtitle2_p.text = slide4_data["subtitle2"]
    subtitle2_p.font.bold = True
    subtitle2_p.font.size = Pt(14)
    subtitle2_p.font.color.rgb = RGBColor(*COLORS["black"])
    subtitle2_p.alignment = 1

    # Create Table 2
    table2_data_with_totals = slide4_data["table2"]["rows"] + [table2_totals]
    table2_rows = len(table2_data_with_totals) + 1 # +1 for header
    table2_cols = len(slide4_data["table2"]["columns"])
    
    # Calculate appropriate table height based on number of rows
    table2_height = Inches(0.4 + (table2_rows * 0.3))  # Header + rows
    table2 = slide.shapes.add_table(table2_rows, table2_cols, table_left, table2_top + Inches(0.4), max_table_width, table2_height).table

    # Set Table 2 column widths
    table2.columns[0].width = Inches(8.5) # Vulnerability
    table2.columns[1].width = Inches(1.5) # Critical
    table2.columns[2].width = Inches(1.5) # Medium
    table2.columns[3].width = Inches(1.8) # Grand Total

    # Set row heights for table 2
    table2.rows[0].height = Inches(0.4)  # Header row
    for i in range(1, table2_rows):
        table2.rows[i].height = Inches(0.3)  # Data rows

    # Table 2 header row
    for i, col_name in enumerate(slide4_data["table2"]["columns"]):
        cell = table2.cell(0, i)
        cell.text = col_name
        cell.fill.solid()
        cell.fill.fore_color.rgb = RGBColor(*COLORS["blue"])
        paragraph = cell.text_frame.paragraphs[0]
        paragraph.font.bold = True
        paragraph.font.size = Pt(FONT_SIZES["table_header"])
        paragraph.font.color.rgb = RGBColor(*COLORS["white"])
        paragraph.alignment = 1

    # Table 2 data rows
    for row_idx, row_data in enumerate(table2_data_with_totals):
        for col_idx, cell_data in enumerate(row_data):
            cell = table2.cell(row_idx + 1, col_idx)
            cell.text = str(cell_data) if cell_data else ""
            paragraph = cell.text_frame.paragraphs[0]
            paragraph.font.size = Pt(FONT_SIZES["table_data"])
            paragraph.font.color.rgb = RGBColor(*COLORS["black"])
            # Center align numbers
            if col_idx > 0:
                paragraph.alignment = 1
            # Blue background for Grand Total row
            if row_data[0] == "Grand Total":
                cell.fill.solid()
                cell.fill.fore_color.rgb = RGBColor(*COLORS["blue"])
                paragraph.font.bold = True
                paragraph.font.color.rgb = RGBColor(*COLORS["white"])
            # Alternate row coloring for data rows
            elif row_idx % 2 == 0:
                cell.fill.solid()
                cell.fill.fore_color.rgb = RGBColor(*COLORS["very_light_gray"])

    end_time = time.time()
    runtime = end_time - start_time
    print(f"Slide 4 created successfully!")
    print(f"Software Exploits Total - Critical: {table1_totals[1]}, High: {table1_totals[2]}, Immediate: {table1_totals[3]}, Medium: {table1_totals[4]}, Grand Total: {table1_totals[5]}")
    print(f"OS Hardening Exploits Total - Critical: {table2_totals[1]}, Medium: {table2_totals[2]}, Grand Total: {table2_totals[3]}")
    print(f"Runtime: {runtime:.4f} seconds")
    return runtime

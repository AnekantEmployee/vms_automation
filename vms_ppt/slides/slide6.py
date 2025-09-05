from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import MSO_ANCHOR
import time
from config_colors import COLORS, FONT_SIZES

def create_slide6(prs: Presentation, slide6_data):
    start_time = time.time()

    # Calculate totals for Stage 1 dynamically
    stage1_total = 0
    stage1_remediation = 0
    stage1_balance = 0
    for row in slide6_data['stage1_table']['rows']:
        if row[1] == 'Total': # Skip if somehow total row exists
            continue
        total_val = int(row[2]) if str(row[2]).isdigit() else 0
        remediation_val = int(row[3]) if str(row[3]).isdigit() else 0
        balance_val = int(row[4]) if str(row[4]).isdigit() else 0
        stage1_total += total_val
        stage1_remediation += remediation_val
        stage1_balance += balance_val

    # Calculate totals for Stage 2 dynamically
    stage2_total = 0
    stage2_balance = 0
    for row in slide6_data['stage2_table']['rows']:
        if row[1] == 'Total': # Skip if somehow total row exists
            continue
        total_val = int(row[2]) if str(row[2]).isdigit() else 0
        balance_val = int(row[4]) if str(row[4]).isdigit() else 0
        stage2_total += total_val
        stage2_balance += balance_val

    # Create calculated totals rows
    stage1_totals_row = ["", "Total", str(stage1_total), str(stage1_remediation), str(stage1_balance), ""]
    stage2_totals_row = ["", "Total", str(stage2_total), "TBD", str(stage2_balance), ""]

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
    p.text = slide6_data["title"]
    p.font.bold = True
    p.font.size = Pt(FONT_SIZES["title"])
    p.font.color.rgb = RGBColor(*COLORS["white"])
    p.alignment = 1

    # Stage 1 table
    stage1_left = Inches(0.5)
    stage1_top = Inches(0.8)
    stage1_width = prs.slide_width - Inches(1.0)

    # Add Stage 1 title
    stage1_title_box = slide.shapes.add_textbox(stage1_left, stage1_top, stage1_width, Inches(0.3))
    stage1_tf = stage1_title_box.text_frame
    stage1_p = stage1_tf.paragraphs[0]
    stage1_p.text = slide6_data["stage1_title"]
    stage1_p.font.bold = True
    stage1_p.font.size = Pt(16)
    stage1_p.font.color.rgb = RGBColor(*COLORS["black"])
    stage1_p.alignment = 1

    # Stage 1 table data (including calculated total)
    stage1_data_with_totals = slide6_data["stage1_table"]["rows"] + [stage1_totals_row]
    stage1_rows = len(stage1_data_with_totals) + 1 # +1 for header
    stage1_cols = len(slide6_data["stage1_table"]["columns"])
    
    # Calculate table height based on number of rows
    stage1_table_height = Inches(0.4 + (stage1_rows * 0.35))  # Header + rows
    table1 = slide.shapes.add_table(stage1_rows, stage1_cols, stage1_left, Inches(1.2), stage1_width, stage1_table_height).table

    # Set Stage 1 column widths
    table1.columns[0].width = Inches(0.5) # #
    table1.columns[1].width = Inches(4.0) # Description
    table1.columns[2].width = Inches(1.5) # Total
    table1.columns[3].width = Inches(2.0) # Remediation Target
    table1.columns[4].width = Inches(1.5) # Balance
    table1.columns[5].width = Inches(1.8) # Timeline

    # Set row heights for stage 1 table
    table1.rows[0].height = Inches(0.4)  # Header row
    for i in range(1, stage1_rows):
        table1.rows[i].height = Inches(0.35)  # Data rows

    # Stage 1 header row
    for i, col_name in enumerate(slide6_data["stage1_table"]["columns"]):
        cell = table1.cell(0, i)
        cell.text = col_name
        cell.fill.solid()
        cell.fill.fore_color.rgb = RGBColor(*COLORS["blue"])
        paragraph = cell.text_frame.paragraphs[0]
        paragraph.font.bold = True
        paragraph.font.size = Pt(FONT_SIZES["table_header"])
        paragraph.font.color.rgb = RGBColor(*COLORS["white"])
        paragraph.alignment = 1

    # Stage 1 data rows
    for row_idx, row_data in enumerate(stage1_data_with_totals):
        for col_idx, cell_data in enumerate(row_data):
            cell = table1.cell(row_idx + 1, col_idx)
            cell.text = str(cell_data)
            paragraph = cell.text_frame.paragraphs[0]
            paragraph.font.size = Pt(FONT_SIZES["table_data"])
            paragraph.font.color.rgb = RGBColor(*COLORS["black"])
            # Center align numbers and # column
            if col_idx == 0 or col_idx > 1:
                paragraph.alignment = 1
            # Blue background for Total row
            if row_data[1] == "Total":
                cell.fill.solid()
                cell.fill.fore_color.rgb = RGBColor(*COLORS["blue"])
                paragraph.font.bold = True
                paragraph.font.color.rgb = RGBColor(*COLORS["white"])
            # Alternate row coloring for data rows
            elif row_idx % 2 == 0:
                cell.fill.solid()
                cell.fill.fore_color.rgb = RGBColor(*COLORS["very_light_gray"])

    # Footnote for Stage 1
    footnote_box = slide.shapes.add_textbox(stage1_left, Inches(1.2) + stage1_table_height + Inches(0.1), stage1_width, Inches(0.2))
    footnote_tf = footnote_box.text_frame
    footnote_p = footnote_tf.paragraphs[0]
    footnote_p.text = slide6_data["footnote"]
    footnote_p.font.size = Pt(8)
    footnote_p.font.color.rgb = RGBColor(*COLORS["black"])
    footnote_p.font.italic = True

    # Stage 2 table
    stage2_top = Inches(1.2) + stage1_table_height + Inches(0.4)

    # Add Stage 2 title
    stage2_title_box = slide.shapes.add_textbox(stage1_left, stage2_top, stage1_width, Inches(0.3))
    stage2_tf = stage2_title_box.text_frame
    stage2_p = stage2_tf.paragraphs[0]
    stage2_p.text = slide6_data["stage2_title"]
    stage2_p.font.bold = True
    stage2_p.font.size = Pt(16)
    stage2_p.font.color.rgb = RGBColor(*COLORS["black"])
    stage2_p.alignment = 1

    # Stage 2 table data (including calculated total)
    stage2_data_with_totals = slide6_data["stage2_table"]["rows"] + [stage2_totals_row]
    stage2_rows = len(stage2_data_with_totals) + 1 # +1 for header
    stage2_cols = len(slide6_data["stage2_table"]["columns"])
    
    # Calculate table height based on number of rows
    stage2_table_height = Inches(0.4 + (stage2_rows * 0.35))  # Header + rows
    table2 = slide.shapes.add_table(stage2_rows, stage2_cols, stage1_left, stage2_top + Inches(0.4), stage1_width, stage2_table_height).table

    # Set Stage 2 column widths (same as Stage 1)
    table2.columns[0].width = Inches(0.5) # #
    table2.columns[1].width = Inches(4.0) # Description
    table2.columns[2].width = Inches(1.5) # Total
    table2.columns[3].width = Inches(2.0) # Remediation Target
    table2.columns[4].width = Inches(1.5) # Balance
    table2.columns[5].width = Inches(1.8) # Timeline

    # Set row heights for stage 2 table
    table2.rows[0].height = Inches(0.4)  # Header row
    for i in range(1, stage2_rows):
        table2.rows[i].height = Inches(0.35)  # Data rows

    # Stage 2 header row
    for i, col_name in enumerate(slide6_data["stage2_table"]["columns"]):
        cell = table2.cell(0, i)
        cell.text = col_name
        cell.fill.solid()
        cell.fill.fore_color.rgb = RGBColor(*COLORS["blue"])
        paragraph = cell.text_frame.paragraphs[0]
        paragraph.font.bold = True
        paragraph.font.size = Pt(FONT_SIZES["table_header"])
        paragraph.font.color.rgb = RGBColor(*COLORS["white"])
        paragraph.alignment = 1

    # Stage 2 data rows
    for row_idx, row_data in enumerate(stage2_data_with_totals):
        for col_idx, cell_data in enumerate(row_data):
            cell = table2.cell(row_idx + 1, col_idx)
            cell.text = str(cell_data)
            paragraph = cell.text_frame.paragraphs[0]
            paragraph.font.size = Pt(FONT_SIZES["table_data"])
            paragraph.font.color.rgb = RGBColor(*COLORS["black"])
            # Center align numbers and # column
            if col_idx == 0 or col_idx > 1:
                paragraph.alignment = 1
            # Blue background for Total row
            if row_data[1] == "Total":
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
    print(f"Slide 6 created successfully!")
    print(f"Stage 1 Calculated Totals - Total: {stage1_total}, Target: {stage1_remediation}, Balance: {stage1_balance}")
    print(f"Stage 2 Calculated Totals - Total: {stage2_total}, Balance: {stage2_balance}")
    print(f"Runtime: {runtime:.4f} seconds")
    return runtime

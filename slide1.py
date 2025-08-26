from pptx.oxml import parse_xml
from pptx.enum.text import PP_ALIGN
from pptx.dml.color import RGBColor
from pptx.util import Inches, Pt, Cm
from pptx.enum.text import MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE
from ppt_data import DARK_BLUE, LIGHT_SKY_BLUE, YELLOW, VULNERABILITIES


def add_vulnerability_content(slide, vulnerabilities, title="Cyberattack Entry Points Identified", content_cfg=""):
    # Calculate total content height needed
    item_height = content_cfg['item_height']
    items_spacing = content_cfg['items_spacing']
    total_content_height = (
        Inches(0.7) +  # Title height with padding
        (len(vulnerabilities) * item_height) + 
        ((len(vulnerabilities) - 1) * items_spacing)
    )
    
    # Calculate starting Y position to center everything vertically
    available_height = content_cfg.get('available_height', Inches(5.5))  # Default slide content height
    start_y = content_cfg['y'] + (available_height - total_content_height) / 2
    
    # Add title background
    title_left = content_cfg['x']
    title_top = start_y
    title_width = content_cfg['width']
    title_height = Inches(0.35)
    
    # Add background rectangle for title
    title_bg = slide.shapes.add_shape(
        1,  # Rectangle shape
        title_left,
        title_top,
        title_width,
        title_height + Inches(0.2)
    )
    title_bg.fill.solid()
    title_bg.fill.fore_color.rgb = DARK_BLUE
    title_bg.line.fill.background()
    
    # Add textbox with vertical centering
    title_box = slide.shapes.add_textbox(title_left, title_top, title_width, title_height + Inches(0.2))
    title_frame = title_box.text_frame
    title_frame.text = title
    
    # Format title with vertical centering
    title_frame.vertical_anchor = MSO_ANCHOR.MIDDLE
    title_p = title_frame.paragraphs[0]
    title_p.alignment = PP_ALIGN.CENTER
    title_run = title_p.runs[0]
    title_run.font.name = 'Arial'
    title_run.font.size = Pt(20)
    title_run.font.bold = True
    title_run.font.color.rgb = RGBColor(255, 255, 255)  # White text
    
    # Move title background behind text
    slide.shapes._spTree.remove(title_bg._element)
    slide.shapes._spTree.insert(-2, title_bg._element)
    
    # Calculate content area dimensions
    items_start_y = title_top + title_height + Inches(0.25)
    
    # Calculate text positioning
    text_left = content_cfg['x'] + content_cfg['text_left_offset']
    text_width = content_cfg['width'] * content_cfg['text_width_ratio']
    
    # Add vulnerability items
    for i, vuln in enumerate(vulnerabilities):
        y_position = items_start_y + (i * (item_height + items_spacing))
        
        # Add background for each item
        item_bg = slide.shapes.add_shape(
            1,  # Rectangle shape
            content_cfg['x'],
            y_position,
            content_cfg['width'],
            item_height
        )
        item_bg.fill.solid()
        item_bg.fill.fore_color.rgb = LIGHT_SKY_BLUE  # Light blue background
        item_bg.line.color.rgb = RGBColor(200, 220, 240)
        item_bg.line.width = Pt(1)
        
        # Add icon
        if vuln.get('icon'):
            icon_left = content_cfg['x'] + content_cfg['icon_margin']
            icon_top = y_position + (item_height - content_cfg['icon_size']) / 2
            icon = slide.shapes.add_picture(
                vuln['icon'],
                icon_left,
                icon_top,
                width=content_cfg['icon_size'],
                height=content_cfg['icon_size']
            )
        
        # Add text with vertical centering
        text_box = slide.shapes.add_textbox(
            text_left,
            y_position,
            text_width,
            item_height
        )
        text_frame = text_box.text_frame
        text_frame.text = vuln['text']
        text_frame.word_wrap = True
        text_frame.vertical_anchor = MSO_ANCHOR.MIDDLE  # Vertical centering
        
        # Format text
        text_p = text_frame.paragraphs[0]
        text_p.alignment = PP_ALIGN.LEFT
        text_run = text_p.runs[0]
        text_run.font.name = 'Arial'
        text_run.font.size = Pt(13)
        text_run.font.color.rgb = RGBColor(51, 51, 51)  # Dark gray

def add_yellow_box_custom_corners(slide):
    """
    Create a yellow box with only top-right corner rounded using XML manipulation
    
    Args:
        slide: PowerPoint slide object
        x, y: Position
        width, height: Dimensions  
        top_right_radius: Corner radius in pixels for top-right corner
        border_width: Border thickness
    """
    x=Cm(0.5)
    y=Cm(11.25)
    width=Cm(8)
    height=Cm(3.5)
    top_right_radius=22
    border_width=Inches(0.02)
    
    # Convert measurements to EMU (English Metric Units)
    x_emu = x.emu
    y_emu = y.emu
    width_emu = width.emu
    height_emu = height.emu
    radius_emu = top_right_radius * 9525  # Convert pixels to EMU
    
    # Create custom shape XML with individual corner radii
    shape_xml = f'''
    <p:sp xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"
          xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
        <p:nvSpPr>
            <p:cNvPr id="1" name="CustomYellowBox"/>
            <p:cNvSpPr/>
            <p:nvPr/>
        </p:nvSpPr>
        <p:spPr>
            <a:xfrm>
                <a:off x="{x_emu}" y="{y_emu}"/>
                <a:ext cx="{width_emu}" cy="{height_emu}"/>
            </a:xfrm>
            <a:custGeom>
                <a:avLst/>
                <a:gdLst/>
                <a:ahLst/>
                <a:cxnLst/>
                <a:rect l="0" t="0" r="{width_emu}" b="{height_emu}"/>
                <a:pathLst>
                    <a:path w="{width_emu}" h="{height_emu}">
                        <a:moveTo>
                            <a:pt x="0" y="0"/>
                        </a:moveTo>
                        <a:lnTo>
                            <a:pt x="{width_emu - radius_emu}" y="0"/>
                        </a:lnTo>
                        <a:arcTo wR="{radius_emu}" hR="{radius_emu}" stAng="16200000" swAng="5400000"/>
                        <a:lnTo>
                            <a:pt x="{width_emu}" y="{height_emu}"/>
                        </a:lnTo>
                        <a:lnTo>
                            <a:pt x="0" y="{height_emu}"/>
                        </a:lnTo>
                        <a:close/>
                    </a:path>
                </a:pathLst>
            </a:custGeom>
            <a:solidFill>
                <a:srgbClr val="FFFF00"/>
            </a:solidFill>
            <a:ln w="{int(border_width.emu)}">
                <a:solidFill>
                    <a:srgbClr val="FFFF00"/>
                </a:solidFill>
            </a:ln>
        </p:spPr>
        <p:txBody>
            <a:bodyPr/>
            <a:lstStyle/>
            <a:p/>
        </p:txBody>
    </p:sp>'''
    
    # Parse and add the custom shape
    shape_element = parse_xml(shape_xml)
    slide.shapes._spTree.append(shape_element)
    
    return slide.shapes[-1]

def create_blank_slide_with_background(p, img_path, top_right_img_path='ppt-generation/bg/yash-logo.png', margin=40):
    # Add slide with blank layout
    slide = p.slides.add_slide(p.slide_layouts[6])
    
    # Add background image
    left = top = 0
    bg_pic = slide.shapes.add_picture(img_path, left, top, width=p.slide_width, height=p.slide_height)
    
    # Send background picture to back
    slide.shapes._spTree.remove(bg_pic._element)
    slide.shapes._spTree.insert(2, bg_pic._element)
    
    # Add top-right image if provided
    if top_right_img_path:
        margin_emu = margin * 9525
        img_width, img_height = 152, 94
        width_emu = img_width * 9525
        height_emu = img_height * 9525
        left_pos = p.slide_width - width_emu - margin_emu
        top_pos = margin_emu
        
        top_right_pic = slide.shapes.add_picture(
            top_right_img_path, left_pos, top_pos, 
            width=width_emu, height=height_emu
        )
    
    # Example: Custom positioning for vulnerability content
    content_cfg = {
        'x': Inches(0),
        'y': Cm(14.75),
        'width': Cm(21),
        'height': None,  # Will be calculated
        'item_height': Inches(1.1),
        'icon_size': Inches(0.6),
        'icon_margin': Inches(0.3),
        'text_left_offset': Inches(1.1),
        'text_width_ratio': 0.8,
        'items_spacing': Inches(0),
    }

    add_vulnerability_content(slide, VULNERABILITIES, content_cfg=content_cfg)
    
    # Basic yellow box
    add_yellow_box_custom_corners(slide)
    
    return slide
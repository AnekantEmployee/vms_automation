def create_blank_slide_with_background(p, img_path):
    """
    Create a blank slide with background image
    """
    # Add slide with blank layout
    slide = p.slides.add_slide(p.slide_layouts[6])
    
    # Add background image
    left = top = 0
    pic = slide.shapes.add_picture(img_path, left, top, width=p.slide_width, height=p.slide_height)
    
    # Send picture to back so other elements appear on top
    slide.shapes._spTree.remove(pic._element)
    slide.shapes._spTree.insert(2, pic._element)
    
    return slide

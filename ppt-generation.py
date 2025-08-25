from pptx.util import Cm
from pptx import Presentation
from slide1 import create_blank_slide_with_background
from slide2 import create_vulnerability_summary_slide

def create_presentation_with_slides():
    """
    Example function showing how to create a presentation with both slide types
    """
    # Slide configuration
    SLIDE_CONFIG = {
        'width': Cm(21),
        'height': Cm(28)
    }
    
    # Create presentation
    p = Presentation()
    
    # Set slide size to A4
    p.slide_width = SLIDE_CONFIG['width']
    p.slide_height = SLIDE_CONFIG['height']
    
    # Create a blank slide with background (Slide 1)
    create_blank_slide_with_background(p, 'ppt-generation/bg/1.jpg')
    
    # Create vulnerability summary slide (Slide 2)
    create_vulnerability_summary_slide(p, 'ppt-generation/bg/2.jpg')
    
    # Save presentation
    p.save('vulnerability_summary_with_table.pptx')
    print("Presentation with two slides created successfully!")
    
    return p

# Call the example function to create the presentation
if __name__ == "__main__":
    create_presentation_with_slides()
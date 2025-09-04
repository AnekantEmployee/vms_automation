import time
from slide_data import *
from pptx import Presentation
from pptx.util import Inches
from slides.slide1 import create_slide1
from slides.slide2 import create_slide2
from slides.slide3 import create_slide3
from slides.slide4 import create_slide4
from slides.slide5 import create_slide5
from slides.slide6 import create_slide6
from slides.slide7 import create_slide7
from slides.slide8 import create_slide8
from slides.slide9 import create_slide9
from slides.slide10 import create_slide10

def main(slide1_data, slide2_data, slide3_data, slide4_data, slide5_data, slide6_data, slide7_data, slide8_data, slide9_data, slide10_data):
    total_start_time = time.time()
    
    # Create a presentation object with 16:9 aspect ratio
    prs = Presentation()
    prs.slide_width = Inches(13.333)   # 16:9 width
    prs.slide_height = Inches(7.5)     # 16:9 height

    print("Creating presentation...")
    
    # Create slide 1 (Agenda)
    print("Creating Slide 1...")
    create_slide1(prs, slide1_data)
    
    # Create slide 2
    print("Creating Slide 2...")
    create_slide2(prs, slide2_data)
    
    # Create slide 3
    print("Creating Slide 3...")
    create_slide3(prs, slide3_data)
    
    # Create slide 4
    print("Creating Slide 4...")
    create_slide4(prs, slide4_data)
    
    # Create slide 5
    print("Creating Slide 5...")
    create_slide5(prs, slide5_data)
    
    # Create slide 6
    print("Creating Slide 6...")
    create_slide6(prs, slide6_data)
    
    # Create slide 7
    print("Creating Slide 7...")
    create_slide7(prs, slide7_data)
    
    # Create slide 8
    print("Creating Slide 8...")
    create_slide8(prs, slide8_data)
    
    # Create slide 9
    print("Creating Slide 9...")
    create_slide9(prs, slide9_data)
    
    # Create slide 10 (OS Hardening Table with calculated totals)
    print("Creating Slide 10...")
    create_slide10(prs, slide10_data)

    # Save the presentation
    prs.save("Vulnerability_Management_Presentation.pptx")
    
    total_end_time = time.time()
    total_runtime = total_end_time - total_start_time
    
    print(f"\n✅ PowerPoint presentation created successfully!")
    print(f"📊 Total slides: 10")
    print(f"⏱️  Total runtime: {total_runtime:.4f} seconds")
    print(f"💾 File saved: Vulnerability_Management_Presentation.pptx")

if __name__ == "__main__":
    main(slide1_data, slide2_data, slide3_data, slide4_data, slide5_data, slide6_data, slide7_data, slide8_data, slide9_data, slide10_data)

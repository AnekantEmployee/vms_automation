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

def main(*slide_data):
    start_time = time.time()
    
    # Create presentation with 16:9 aspect ratio
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)

    # Create slides
    slide_functions = [create_slide1, create_slide2, create_slide3, create_slide4, create_slide5, create_slide6, create_slide7, create_slide8, create_slide9, create_slide10]
    
    for i, (func, data) in enumerate(zip(slide_functions, slide_data), 1):
        print(f"Creating Slide {i}...")
        func(prs, data)

    # Save presentation
    prs.save("Test Report 2.pptx")
    
    runtime = time.time() - start_time
    print(f"\n✅ Presentation created! 📊 10 slides ⏱️ {runtime:.4f}s")
    print(f"💾 File: Test Report 1.pptx")

if __name__ == "__main__":
    main(slide1_data, slide2_data, slide3_data, slide4_data, slide5_data, 
         slide6_data, slide7_data, slide8_data, slide9_data, slide10_data)
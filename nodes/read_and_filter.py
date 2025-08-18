import pandas as pd
from components.process_excel import create_observations_sheet


def read_and_filter_node(state):
    """
    First node: Read input file and return all data without filtering
    """
    try:
        print(f"📖 Reading input file: {state['input_file']}")

        # Read the source data
        if state["source_sheet"]:
            df = pd.read_excel(state["input_file"], sheet_name=state["source_sheet"])
            print(f"Successfully read sheet '{state['source_sheet']}'")
        else:
            df = pd.read_excel(state["input_file"])
            print(f"Successfully read default sheet")

        print(f"Original data shape: {df.shape}")
        
        # Create observations sheet
        observations_df = create_observations_sheet(df)
        
        if observations_df.empty:
            print("No observations data was created")
        else:
            print(f"Observations data shape: {observations_df.shape}")

        return {
            "success": True,
            "error": None,
            "original_df": df,
            "observations_df": observations_df,
        }

    except Exception as e:
        print(f"✗ Error in read_and_filter_node: {e}")
        return {"success": False, "error": str(e)}
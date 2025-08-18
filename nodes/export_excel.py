import openpyxl
import pandas as pd
from components.process_excel import style_excel_sheet


def export_excel_node(state):
    """
    Final node: Export all sheets to Excel file with styling
    """
    try:
        print(f"💾 Exporting to Excel: {state['output_file']}")

        if not state.get("success", False):
            raise Exception("Previous nodes failed")

        # Get all DataFrames
        original_df = state["original_df"]
        observations_df = state["observations_df"]
        findings_df = state["enriched_findings_df"]

        # Save to Excel with multiple sheets
        with pd.ExcelWriter(state["output_file"], engine="openpyxl") as writer:
            # Save the important columns sheet
            if original_df is not None and not original_df.empty:
                original_df.to_excel(
                    writer, sheet_name="Original Data", index=False
                )
                print(
                    f"✓ Saved Important_Columns sheet ({original_df.shape[0]} rows, {original_df.shape[1]} cols)"
                )

            # Save observations sheet if it has data
            if observations_df is not None and not observations_df.empty:
                observations_df.to_excel(writer, sheet_name="Observations", index=False)
                print(
                    f"✓ Saved Observations sheet ({observations_df.shape[0]} rows, {observations_df.shape[1]} cols)"
                )

            # Save findings sheet
            if findings_df is not None and not findings_df.empty:
                findings_df.to_excel(writer, sheet_name="Findings", index=False)
                print(
                    f"✓ Saved Findings sheet ({findings_df.shape[0]} rows, {findings_df.shape[1]} cols)"
                )

        # Apply styling to all sheets
        workbook = openpyxl.load_workbook(state["output_file"])
        for sheet_name in workbook.sheetnames:
            worksheet = workbook[sheet_name]
            style_excel_sheet(worksheet)
            print(f"✓ Applied styling to {sheet_name} sheet")

        workbook.save(state["output_file"])
        print(f"🎉 Excel processing completed successfully: {state['output_file']}")

        return {"success": True, "error": None}

    except Exception as e:
        print(f"✗ Error in export_excel_node: {e}")
        return {"success": False, "error": str(e)}

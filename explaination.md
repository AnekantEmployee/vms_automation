VMS Agent Capability Deck you need to create it is taking teh report from teh Qualys then for each vulnerability/row it is findings top cve ids matching from various sources like NIST NVD, CVE.org, OSV DB

It will give all the details for teh cve

Risk agent will be workin which will be showing risk details - Risk_Category Risk_Score Risk_Details Business_ImpactRemediation_Urgency Risk_Immediate_Actions Exploitation_Methods

REmediation Agent will be showing Remediation_Guide Remediation_Priority Estimated_Effort Immediate_Actions Detailed_Steps Verification_Steps Rollback_Plan Reference_Links Additional_Resources

It will be showing exploitability status of the CVE with teh reference github links for teh exploitation if it has happened already

Asset Criticality also it will show as per teh assets used by the organizaiton

Phase 1 — utils/logger.py (foundation, already mostly done, minor tweaks)

Phase 2 — report.py (main orchestrator + threading)

Phase 3 — enhanced_cve_search/improved_cve_search.py (CVE search pipeline)

Phase 4 — enhanced_cve_search/threaded_cve_validator.py (threaded validation)

Phase 5 — utils/remediation_agent.py + utils/risk_assessment.py + enhanced_cve_search/exploit_search.py

from report.py can you implement comprehensive logging in each step note that there is threading so for that can you provide me sturcutred response if possible also logging file should be different for each run save it in a folder seprately and add in gitignore dont miss anything in logging everything I wnat

somethings already done please complete

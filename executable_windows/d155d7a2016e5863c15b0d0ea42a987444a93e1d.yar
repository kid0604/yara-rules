import "pe"

rule INDICATOR_RMM_Atera
{
	meta:
		author = "ditekSHen"
		description = "Detects Atera. Review RMM Inventory"
		clamav1 = "INDICATOR.Win.RMM.Atera"
		reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
		reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
		reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
		reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "SOFTWARE\\ATERA Networks\\AlphaAgent" wide
		$s2 = "Monitoring & Management Agent by ATERA" ascii wide
		$s3 = "agent-api-{0}.atera.com" wide
		$s4 = "agent-api.atera.com" wide
		$s5 = "acontrol.atera.com" wide
		$s6 = /Agent\/(PingReply|GetCommandsFallback|GetCommands|GetTime|GetEnvironmentStatus|GetRecurringPackages|AgentStarting|AcknowledgeCommands)/ wide
		$s7 = "\\AlphaControlAgent\\obj\\Release\\AteraAgent.pdb" ascii
		$s8 = "AteraWebAddress" ascii
		$s9 = "AlphaControlAgent.CloudLogsManager+<>" ascii

	condition:
		uint16(0)==0x5a4d and 4 of them
}

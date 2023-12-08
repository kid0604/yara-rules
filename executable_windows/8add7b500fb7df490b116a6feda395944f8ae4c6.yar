import "pe"

rule INDICATOR_RMM_PulseWay_PCMonTaskSrv
{
	meta:
		author = "ditekSHen"
		description = "Detects Pulseway pcmontask and service user agent responsible for Remote Control, Screens View, Computer Lock, etc"
		clamav1 = "INDICATOR.Win.RMM.PulseWay"
		reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
		reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
		reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
		reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "MM.Monitor." ascii
		$s2 = "RDAgentSessionSettingsV" ascii
		$s3 = "CheckForMacOSRemoteDesktopUpdateCompletedEvent" ascii
		$s4 = "ConfirmAgentStarted" ascii
		$s5 = "GetScreenshot" ascii
		$s6 = "UnloadRemoteDesktopDlls" ascii
		$s7 = "CtrlAltDeleteProc" ascii
		$s8 = "$7cfc3b88-6dc4-49fc-9f0a-bf9e9113a14d" ascii
		$s9 = "computermonitor.mmsoft.ro" ascii

	condition:
		( uint16(0)==0x5a4d or uint16(0)==0xcfd0) and 7 of them
}

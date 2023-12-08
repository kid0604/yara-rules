import "pe"

rule INDICATOR_RMM_ManageEngine_ZohoMeeting
{
	meta:
		author = "ditekSHen"
		description = "Detects ManageEngine Zoho Meeting (dc_rds.exe)"
		clamav1 = "INDICATOR.Win.RMM.ManageEngine-ZohoMeeting"
		reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
		reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
		reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
		reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "bin\\ClientAuthHandler.dll" wide
		$s2 = "AgentHook.dll" wide
		$s3 = "UEMS - Remote Control" wide
		$s4 = "Install hook...." wide
		$s5 = "india.adventnet.com/meet.sas?k=" ascii
		$s6 = "dcTcpSocket::" ascii
		$s7 = "%s/%s?clientId=%s&sessionId=%s&clientName=%s&ticket=%s&connectionId=%s" ascii
		$s8 = ".\\engines\\ccgost\\gost_" ascii

	condition:
		uint16(0)==0x5a4d and 5 of them
}

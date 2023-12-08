import "pe"

rule INDICATOR_RMM_PulseWay_RemoteDesktop
{
	meta:
		author = "ditekSHen"
		description = "Detects Pulseway Rempte Desktop client"
		clamav1 = "INDICATOR.Win.RMM.PulseWay"
		reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
		reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
		reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
		reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "RemoteControl" ascii
		$s2 = "MM.Monitor.RemoteDesktopClient." ascii
		$s3 = "MM.Monitor.RemoteControl" ascii
		$s4 = "RemoteDesktopClientUpdateInfo" ascii
		$s5 = "ShowRemoteDesktopEnabledSystemsOnly" ascii
		$s6 = "$31f50968-d45c-49d6-ace9-ebc790855a51" ascii

	condition:
		( uint16(0)==0x5a4d or uint16(0)==0xcfd0) and 5 of them
}

import "pe"

rule INDICATOR_RMM_SplashtopStreamer
{
	meta:
		author = "ditekSHen"
		description = "Detects Splashtop Streamer. Review RMM Inventory"
		clamav1 = "INDICATOR.Win.RMM.SplashtopStreamer"
		reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
		reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
		reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
		reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\slave\\workspace\\GIT_WIN_SRS_Formal\\Source\\irisserver\\" ascii
		$s2 = ".api.splashtop.com" wide
		$s3 = "Software\\Splashtop Inc.\\Splashtop" wide
		$s4 = "restarted the streamer.%nApp version: %1" wide
		$s5 = "Splashtop-Splashtop Streamer-" wide
		$s6 = "[RemoveStreamer] Send msg 2 cloud(%d:%d:%d)" wide

	condition:
		uint16(0)==0x5a4d and 4 of them
}

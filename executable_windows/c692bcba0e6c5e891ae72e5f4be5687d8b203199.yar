import "pe"

rule INDICATOR_RMM_FleetDeck_Agent
{
	meta:
		author = "ditekSHen"
		description = "Detects FleetDeck Agent. Review RMM Inventory"
		clamav1 = "INDICATOR.Win.RMM.FleetDeckAgent"
		reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
		reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
		reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
		reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "fleetdeck.io/" ascii
		$s2 = "load FleetDeck agent" ascii
		$s3 = ".dev1.fleetdeck.io" ascii
		$s4 = "remoteDesktopSessionMutex" ascii
		$s5 = "main.remoteDesktopWatchdog" fullword ascii
		$s6 = "main.virtualTerminalWatchdog" fullword ascii
		$s7 = "main.meetRemoteDesktop" fullword ascii
		$s8 = "repo.senri.se/prototype3/" ascii
		$s9 = "main.svcIpcClient" fullword ascii
		$s10 = "main.hookMqttLogging" fullword ascii

	condition:
		uint16(0)==0x5a4d and 4 of them
}

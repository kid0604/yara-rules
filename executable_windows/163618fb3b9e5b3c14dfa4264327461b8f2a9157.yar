import "pe"

rule INDICATOR_RMM_FleetDeck_Commander
{
	meta:
		author = "ditekSHen"
		description = "Detects FleetDeck Commander. Review RMM Inventory"
		clamav1 = "INDICATOR.Win.RMM.FleetDeckCommander"
		reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
		reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
		reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
		reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Software\\Microsoft\\FleetDeck Commander" ascii
		$s2 = "fleetdeck.io/prototype3/" ascii
		$s3 = "fleetdeck_commander_launcher.exe" ascii
		$s4 = "fleetdeck_commander_svc.exe" ascii
		$s5 = "|FleetDeck Commander" ascii
		$s6 = "c:\\agent\\_work\\66\\s\\" ascii

	condition:
		uint16(0)==0x5a4d and 4 of them
}

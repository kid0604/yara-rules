import "pe"

rule INDICATOR_RMM_FleetDeck_Commander_Launcher
{
	meta:
		author = "ditekSHen"
		description = "Detects FleetDeck Commander Launcher. Review RMM Inventory"
		clamav1 = "INDICATOR.Win.RMM.FleetDeckCommander-Launcher"
		reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
		reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
		reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
		reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "fleetdeck.io/prototype3/commander_launcher" ascii
		$s2 = "FleetDeck Commander Launcher" ascii

	condition:
		uint16(0)==0x5a4d and all of them
}

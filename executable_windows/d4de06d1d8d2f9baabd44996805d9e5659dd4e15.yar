import "pe"

rule INDICATOR_RMM_AeroAdmin
{
	meta:
		author = "ditekSHen"
		description = "Detects AeroAdmin. Review RMM Inventory"
		clamav1 = "INDICATOR.Win.RMM.AeroAdmin"
		reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
		reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
		reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
		reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\AeroAdmin" wide
		$s2 = ".aeroadmin.com" ascii wide
		$s3 = "XAeroadminAppRestarter" wide
		$s4 = "SYSTEM\\ControlSet001\\Control\\SafeBoot\\Network\\AeroadminService" wide
		$s5 = "AeroAdmin {}" ascii
		$s6 = "FAeroAdmin.cpp" fullword ascii
		$s7 = "Referer: http://900100.net" ascii
		$s8 = "POST /sims/sims_new.php" ascii
		$s9 = "aeroadmin.pdb" ascii

	condition:
		uint16(0)==0x5a4d and 4 of them
}

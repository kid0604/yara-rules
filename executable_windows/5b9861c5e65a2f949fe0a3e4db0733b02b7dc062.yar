import "pe"

rule MAL_APT_NK_Andariel_Grease2
{
	meta:
		author = "CISA.gov (modified by Florian Roth, Nextron Systems)"
		description = "Detects the Grease2 malware family used by Andariel"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
		date = "2024-07-25"
		modified = "2024-07-26"
		score = 80
		id = "4defbe08-b3c6-5ab9-9a57-cec57ff42d9a"
		os = "windows"
		filetype = "executable"

	strings:
		$str_rdpconf = "emp\\RDPConf.exe"
		$str_rdpwinst = "emp\\RDPWInst.exe"
		$str_net_user = "net user"
		$str_admins_add = "net localgroup administrators"

	condition:
		uint16(0)==0x5A4D and all of them
}

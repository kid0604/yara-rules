rule APT_Sandworm_CyclopsBlink_core_command_check
{
	meta:
		author = "NCSC"
		description = "Detects the code bytes used to test the command ID being sent to the core component of Cyclops Blink"
		hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
		hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"
		reference = "https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter"
		date = "2022-02-23"
		os = "windows"
		filetype = "executable"

	strings:
		$cmd_check = {81 3F 00 18 88 09 00 05 54 00 06 3E 2F 80 00 (07|0A|0B|0C|0D) }

	condition:
		( uint32(0)==0x464c457f) and (#cmd_check==5)
}

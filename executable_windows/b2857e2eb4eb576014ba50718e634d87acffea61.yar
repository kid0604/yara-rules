rule Eight_Base_Ransomware
{
	meta:
		Description = "Rule for Detecting 8Base Rasonmware and all phobos family"
		author = "@FarghlyMal"
		Cape_type = "8Base payload"
		Date = "8/18/2023"
		description = "Rule for detecting 8Base Ransomware and all Phobos family"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "ID" wide
		$s2 = "ELVL" wide
		$s3 = "\\?\\X:" wide
		$s4 = "\\?\\ :" wide
		$s5 = "\\*" wide
		$s6 = "<<" wide
		$s7 = ">>" wide
		$s8 = {5fab7a945c0a134cb4d64bf7836fc9f8}

	condition:
		uint16(0)==0x5A4D and 7 of ($s*) and filesize <70KB
}

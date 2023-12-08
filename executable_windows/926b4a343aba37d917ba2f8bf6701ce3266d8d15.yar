rule PassSniffer_alt_1
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file PassSniffer.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "dcce4c577728e8edf7ed38ac6ef6a1e68afb2c9f"
		os = "windows"
		filetype = "executable"

	strings:
		$s2 = "Sniff" fullword ascii
		$s3 = "GetLas" fullword ascii
		$s4 = "VersionExA" fullword ascii
		$s10 = " Only RuntUZ" fullword ascii
		$s12 = "emcpysetprintf\\" fullword ascii
		$s13 = "WSFtartup" fullword ascii

	condition:
		all of them
}

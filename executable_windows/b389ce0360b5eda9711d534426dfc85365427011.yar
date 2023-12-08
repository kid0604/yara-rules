rule Carbanak_0915_2
{
	meta:
		description = "Carbanak Malware"
		author = "Florian Roth"
		reference = "https://www.csis.dk/en/csis/blog/4710/"
		date = "2015-09-03"
		score = 70
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "8Rkzy.exe" fullword wide
		$s1 = "Export Template" fullword wide
		$s2 = "Session folder with name '%s' already exists." fullword ascii
		$s3 = "Show Unconnected Endpoints (Ctrl+U)" fullword ascii
		$s4 = "Close All Documents" fullword wide
		$s5 = "Add &Resource" fullword ascii
		$s6 = "PROCEXPLORER" fullword wide
		$s7 = "AssocQueryKeyA" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <500KB and ($x1 or all of ($s*))
}

rule snifferport
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file snifferport.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "d14133b5eaced9b7039048d0767c544419473144"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "iphlpapi.DLL" fullword ascii
		$s5 = "ystem\\CurrentCorolSet\\" fullword ascii
		$s11 = "Port.TX" fullword ascii
		$s12 = "32Next" fullword ascii
		$s13 = "V1.2 B" fullword ascii

	condition:
		all of them
}

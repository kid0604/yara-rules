rule PassCV_Sabre_Malware_5
{
	meta:
		description = "PassCV Malware mentioned in Cylance Report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.cylance.com/digitally-signed-malware-targeting-gaming-companies"
		date = "2016-10-20"
		hash1 = "03aafc5f468a84f7dd7d7d38f91ff17ef1ca044e5f5e8bbdfe589f5509b46ae5"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "ncircTMPg" fullword ascii
		$x2 = "~SHELL#" fullword ascii
		$x3 = "N.adobe.xm" fullword ascii
		$s1 = "NEL32.DLL" fullword ascii
		$s2 = "BitLocker.exe" fullword wide
		$s3 = "|xtplhd" fullword ascii
		$s4 = "SERVICECORE" fullword wide
		$s5 = "SHARECONTROL" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <4000KB and 1 of ($x*) or all of ($s*))
}

rule Ransom_BadEncript
{
	meta:
		description = "Detect the risk of Ransomware BadEncript Rule 1"
		hash1 = "3bba4636606843da8e3591682b4433bdc94085a1939bbdc35f10bbfd97ac3d3d"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "c:\\users\\nikitos\\documents\\visual studio 2015\\Projects\\BadEncriptMBR\\Release\\BadEncriptMBR.pdb" fullword ascii
		$s2 = "DoctorPetrovic.org" fullword wide
		$s3 = "oh lol it failed" fullword ascii
		$s4 = "Allows DoctorPetrovic Scanner" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <400KB and ( any of ($x*) or 2 of them )
}

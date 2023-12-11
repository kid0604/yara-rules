import "pe"

rule EquationGroup_EquationDrug_tdi6
{
	meta:
		description = "EquationGroup Malware - file tdi6.sys"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/tcSoiJ"
		date = "2017-01-13"
		hash1 = "12c082f74c0916a0e926488642236de3a12072a18d29c97bead15bb301f4b3f8"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "tdi6.sys" fullword wide
		$s3 = "TDI IPv6 Wrapper" fullword wide
		$s5 = "Corporation. All rights reserved." fullword wide
		$s6 = "FailAction" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and all of them )
}

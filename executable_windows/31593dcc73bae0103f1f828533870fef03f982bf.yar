import "pe"

rule EquationGroup_EquationDrug_Gen_6
{
	meta:
		description = "EquationGroup Malware - file PC_Level3_dll_x64"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/tcSoiJ"
		date = "2017-01-13"
		hash1 = "339855618fb3ef53987b8c14a61bd4519b2616e766149e0c21cbd7cbe7a632c9"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Psxssdll.dll" fullword wide
		$s2 = "Posix Server Dll" fullword wide
		$s3 = "Copyright (C) Microsoft" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}

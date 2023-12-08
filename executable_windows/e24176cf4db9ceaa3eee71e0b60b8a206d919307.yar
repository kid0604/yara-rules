import "pe"

rule EquationGroup_ModifyGroup_Lp
{
	meta:
		description = "EquationGroup Malware - file ModifyGroup_Lp.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/tcSoiJ"
		date = "2017-01-13"
		hash1 = "dfb38ed2ca3870faf351df1bd447a3dc4470ed568553bf83df07bf07967bf520"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Modify Privileges failed" fullword wide
		$s2 = "Given privilege name not found" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}

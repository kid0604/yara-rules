import "pe"

rule EquationGroup_modifyAudit_Implant
{
	meta:
		description = "EquationGroup Malware - file modifyAudit_Implant.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/tcSoiJ"
		date = "2017-01-13"
		hash1 = "b7902809a15c4c3864a14f009768693c66f9e9234204b873d29a87f4c3009a50"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "LSASS.EXE" fullword wide
		$s2 = "hNtQueryInformationProcess" fullword ascii
		$s3 = "hZwOpenProcess" fullword ascii
		$s4 = ".?AVFeFinallyFailure@@" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <90KB and ( all of ($s*))) or ( all of them )
}

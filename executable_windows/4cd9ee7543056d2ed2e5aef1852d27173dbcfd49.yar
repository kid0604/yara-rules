import "pe"

rule EquationGroup_processinfo_Implant
{
	meta:
		description = "EquationGroup Malware - file processinfo_Implant.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/tcSoiJ"
		date = "2017-01-13"
		hash1 = "aadfa0b1aec4456b10e4fb82f5cfa918dbf4e87d19a02bcc576ac499dda0fb68"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "hZwOpenProcessToken" fullword ascii
		$s2 = "hNtQueryInformationProcess" fullword ascii
		$s3 = "No mapping" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <80KB and all of them )
}

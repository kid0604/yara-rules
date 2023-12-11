import "pe"

rule EquationGroup_EventLogEdit_Implant
{
	meta:
		description = "EquationGroup Malware - file EventLogEdit_Implant.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/tcSoiJ"
		date = "2017-01-13"
		hash1 = "0bb750195fbd93d174c2a8e20bcbcae4efefc881f7961fdca8fa6ebd68ac1edf"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "SYSTEM\\CurrentControlSet\\Services\\EventLog\\%ls" fullword wide
		$s2 = "Ntdll.dll" fullword ascii
		$s3 = "hZwOpenProcess" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and all of them )
}

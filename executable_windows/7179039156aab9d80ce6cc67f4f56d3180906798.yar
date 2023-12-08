import "pe"

rule EquationGroup_PC_Level4_flav_exe
{
	meta:
		description = "EquationGroup Malware - file PC_Level4_flav_exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/tcSoiJ"
		date = "2017-01-13"
		hash1 = "33ba9f103186b6e52d8d69499512e7fbac9096e7c5278838127488acc3b669a9"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Extended Memory Runtime Process" fullword wide
		$s2 = "memess.exe" fullword wide
		$s3 = "\\\\.\\%hs" fullword ascii
		$s4 = ".?AVOpenSocket@@" fullword ascii
		$s5 = "Corporation. All rights reserved." fullword wide
		$s6 = "itanium" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of them )
}

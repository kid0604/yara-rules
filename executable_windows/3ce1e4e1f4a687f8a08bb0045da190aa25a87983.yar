import "pe"

rule EquationGroup_PC_Level4_flav_dll_x64
{
	meta:
		description = "EquationGroup Malware - file PC_Level4_flav_dll_x64"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/tcSoiJ"
		date = "2017-01-13"
		hash1 = "25a2549031cb97b8a3b569b1263c903c6c0247f7fff866e7ec63f0add1b4921c"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "wship.dll" fullword wide
		$s2 = "   IP:      " fullword ascii
		$s3 = "\\\\.\\%hs" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of them )
}

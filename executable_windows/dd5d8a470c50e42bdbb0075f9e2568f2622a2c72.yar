import "pe"

rule EquationGroup_ProcessOptions_Lp
{
	meta:
		description = "EquationGroup Malware - file ProcessOptions_Lp.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/tcSoiJ"
		date = "2017-01-13"
		hash1 = "31d86f77137f0b3697af03dd28d6552258314cecd3c1d9dc18fcf609eb24229a"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Invalid parameter received by implant" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}

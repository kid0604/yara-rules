import "pe"

rule INDICATOR_EXE_Packed_Bonsai
{
	meta:
		author = "ditekSHen"
		description = "Detects .NET executables developed using Bonsai"
		os = "windows"
		filetype = "executable"

	strings:
		$bonsai1 = "<Bonsai." ascii
		$bonsai2 = "Bonsai.Properties" ascii
		$bonsai3 = "Bonsai.Core.dll" fullword wide
		$bonsai4 = "Bonsai.Design." wide

	condition:
		uint16(0)==0x5a4d and 2 of ($bonsai*)
}

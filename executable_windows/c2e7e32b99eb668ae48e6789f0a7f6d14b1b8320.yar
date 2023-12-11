rule EquationGroup_Toolset_Apr17_wmi_Implant
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "de08d6c382faaae2b4b41b448b26d82d04a8f25375c712c12013cb0fac3bc704"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "SELECT ProcessId,Description,ExecutablePath FROM Win32_Process" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <50KB and all of them )
}

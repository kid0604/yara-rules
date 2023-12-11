rule EquationGroup_Toolset_Apr17_RemoteExecute_Target
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "4a649ca8da7b5499821a768c650a397216cdc95d826862bf30fcc4725ce8587f"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Win32_Process" fullword ascii
		$s2 = "\\\\%ls\\root\\cimv2" fullword wide
		$op1 = { 83 7b 18 01 75 12 83 63 }

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of them )
}

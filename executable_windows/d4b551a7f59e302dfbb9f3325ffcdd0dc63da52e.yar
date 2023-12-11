rule EquationGroup_Toolset_Apr17_Shares_Target
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "6c57fb33c5e7d2dee415ae6168c9c3e0decca41ffe023ff13056ff37609235cb"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Select * from Win32_Share" fullword ascii
		$s2 = "slocalhost" fullword wide
		$s3 = "\\\\%ls\\root\\cimv2" fullword wide
		$s4 = "\\\\%ls\\%ls" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of them )
}

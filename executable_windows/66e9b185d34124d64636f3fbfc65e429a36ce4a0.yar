rule EquationGroup_Toolset_Apr17_ActiveDirectory_Target
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "33c1b7fdee7c70604be1e7baa9eea231164e62d5d5090ce7f807f43229fe5c36"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "(&(objectCategory=person)(objectClass=user)(cn=" fullword wide
		$s2 = "(&(objectClass=user)(objectCategory=person)" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of them )
}

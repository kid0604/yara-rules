rule EquationGroup_Toolset_Apr17_PC_Exploit
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "77486bb828dba77099785feda0ca1d4f33ad0d39b672190079c508b3feb21fb0"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\\\.\\pipe\\pcheap_reuse" fullword wide
		$s2 = "**** FAILED TO DUPLICATE SOCKET ****" fullword wide
		$s3 = "**** UNABLE TO DUPLICATE SOCKET TYPE %u ****" fullword wide
		$s4 = "YOU CAN IGNORE ANY 'ServiceEntry returned error' messages after this..." fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <20KB and 1 of them )
}

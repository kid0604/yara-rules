rule EquationGroup_Toolset_Apr17_Namedpipetouch_2_0_0
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "cb5849fcbc473c7df886828d225293ffbd8ee58e221d03b840fd212baeda6e89"
		hash2 = "043d1c9aae6be65f06ab6f0b923e173a96b536cf84e57bfd7eeb9034cd1df8ea"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "[*] Summary: %d pipes found" fullword ascii
		$s3 = "[+] Testing %d pipes" fullword ascii
		$s6 = "[-] Error on SMB startup, aborting" fullword ascii
		$s12 = "92a761c29b946aa458876ff78375e0e28bc8acb0" fullword ascii
		$op1 = { 68 10 10 40 00 56 e8 e1 }

	condition:
		( uint16(0)==0x5a4d and filesize <40KB and 2 of them )
}

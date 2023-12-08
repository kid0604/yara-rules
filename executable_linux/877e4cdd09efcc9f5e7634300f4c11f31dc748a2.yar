rule EquationGroup_libXmexploit2
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file libXmexploit2.8"
		author = "Florian Roth"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		date = "2017-04-08"
		hash1 = "d7ed0234d074266cb37dd6a6a60119adb7d75cc6cc3b38654c8951b643944796"
		os = "linux"
		filetype = "executable"

	strings:
		$s1 = "Usage: ./exp command display_to_return_to" fullword ascii
		$s2 = "sizeof shellcode = %d" fullword ascii
		$s3 = "Execve failed!" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <40KB and 1 of them )
}

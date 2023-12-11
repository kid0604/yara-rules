rule EquationGroup_Toolset_Apr17_Gen2
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		super_rule = 1
		hash1 = "7fe425cd040608132d4f4ab2671e04b340a102a20c97ffdcf1b75be43a9369b5"
		hash2 = "561c0d4fc6e0ff0a78613d238c96aed4226fbb7bb9ceea1d19bc770207a6be1e"
		hash3 = "f2e90e04ddd05fa5f9b2fec024cd07365aebc098593d636038ebc2720700662b"
		hash4 = "8f7e10a8eedea37ee3222c447410fd5b949bd352d72ef22ef0b2821d9df2f5ba"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "[+] Setting password : (NULL)" fullword ascii
		$s2 = "[-] TbBuffCpy() failed!" fullword ascii
		$s3 = "[+] SMB negotiation" fullword ascii
		$s4 = "12345678-1234-ABCD-EF00-0123456789AB" fullword ascii
		$s5 = "Value must end with 0000 (2 NULLs)" fullword ascii
		$s6 = "[*] Configuring Payload" fullword ascii
		$s7 = "[*] Connecting to listener" fullword ascii
		$op1 = { b0 42 40 00 89 44 24 30 c7 44 24 34 }
		$op2 = { eb 59 8b 4c 24 10 68 1c 46 }

	condition:
		( uint16(0)==0x5a4d and filesize <80KB and 1 of ($s*) and 1 of ($op*)) or 3 of them
}

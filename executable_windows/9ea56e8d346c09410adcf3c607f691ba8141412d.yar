rule EquationGroup_Toolset_Apr17_Explodingcantouch_1_2_1
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "0cdde7472b077610d0068aa7e9035da89fe5d435549749707cae24495c8d8444"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "[-] Connection closed by remote host (TCP Ack/Fin)" fullword ascii
		$s2 = "[!]Warning: Error on first request - path size may actually be larger than indicated." fullword ascii
		$s4 = "<http://%s/%s> (Not <locktoken:write1>) <http://%s/>" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <150KB and 1 of them )
}

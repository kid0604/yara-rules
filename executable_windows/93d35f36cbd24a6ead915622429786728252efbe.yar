rule EquationGroup_Toolset_Apr17__ESKE_RPC2_8
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		super_rule = 1
		hash1 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
		hash2 = "5c0896dbafc5d8cc19b1bc7924420b20ed5999ac5bee2cb5a91aada0ea01e337"
		os = "windows"
		filetype = "executable"

	strings:
		$s4 = "Fragment: Packet too small to contain RPC header" fullword ascii
		$s5 = "Fragment pickup: SmbNtReadX failed" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <700KB and 1 of them )
}

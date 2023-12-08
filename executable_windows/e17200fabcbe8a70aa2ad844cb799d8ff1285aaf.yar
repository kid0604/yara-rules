rule EquationGroup_Toolset_Apr17__ecwi_ESKE_EVFR_RPC2_2
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		super_rule = 1
		hash1 = "c4152f65e45ff327dade50f1ac3d3b876572a66c1ce03014f2877cea715d9afd"
		hash2 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
		hash3 = "c5e119ff7b47333f415aea1d2a43cb6cb322f8518562cfb9b90399cac95ac674"
		hash4 = "5c0896dbafc5d8cc19b1bc7924420b20ed5999ac5bee2cb5a91aada0ea01e337"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Target is share name" fullword ascii
		$s2 = "Could not make UdpNetbios header -- bailing" fullword ascii
		$s3 = "Request non-NT session key" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and all of them )
}

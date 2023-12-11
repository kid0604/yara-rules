rule EquationGroup_Toolset_Apr17__ELV_ESKE_ETBL_ETRE_EVFR_11
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		super_rule = 1
		hash1 = "f7fad44560bc8cc04f03f1d30b6e1b4c5f049b9a8a45464f43359cbe4d1ce86f"
		hash2 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
		hash3 = "70db3ac2c1a10de6ce6b3e7a7890c37bffde006ea6d441f5de6d8329add4d2ef"
		hash4 = "e0f05f26293e3231e4e32916ad8a6ee944af842410c194fce8a0d8ad2f5c54b2"
		hash5 = "c5e119ff7b47333f415aea1d2a43cb6cb322f8518562cfb9b90399cac95ac674"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Target is vulnerable" fullword ascii
		$x2 = "Target is NOT vulnerable" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and 1 of them )
}

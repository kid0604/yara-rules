rule EquationGroup_Toolset_Apr17__ELV_ESKE_EVFR_RideArea2_12
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		super_rule = 1
		hash1 = "f7fad44560bc8cc04f03f1d30b6e1b4c5f049b9a8a45464f43359cbe4d1ce86f"
		hash2 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
		hash3 = "c5e119ff7b47333f415aea1d2a43cb6cb322f8518562cfb9b90399cac95ac674"
		hash4 = "e702223ab42c54fff96f198611d0b2e8a1ceba40586d466ba9aadfa2fd34386e"
		os = "windows"
		filetype = "executable"

	strings:
		$x2 = "** CreatePayload ** - EXCEPTION_EXECUTE_HANDLER" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and all of them )
}

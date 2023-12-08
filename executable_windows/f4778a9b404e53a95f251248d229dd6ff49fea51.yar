rule EquationGroup_Toolset_Apr17__ELV_ESKE_13
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		super_rule = 1
		hash1 = "f7fad44560bc8cc04f03f1d30b6e1b4c5f049b9a8a45464f43359cbe4d1ce86f"
		hash2 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Skip call to PackageRideArea().  Payload has already been packaged. Options -x and -q ignored." fullword ascii
		$s2 = "ERROR: pGvars->pIntRideAreaImplantPayload is NULL" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <600KB and 1 of them )
}

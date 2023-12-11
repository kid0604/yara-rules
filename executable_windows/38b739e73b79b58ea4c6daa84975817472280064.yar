rule dbexpora
{
	meta:
		description = "Chinese Hacktool Set - file dbexpora.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b55b007ef091b2f33f7042814614564625a8c79f"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "SELECT A.USER FROM SYS.USER_USERS A " fullword ascii
		$s12 = "OCI 8 - OCIDescriptorFree" fullword ascii
		$s13 = "ORACommand *" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <835KB and all of them
}

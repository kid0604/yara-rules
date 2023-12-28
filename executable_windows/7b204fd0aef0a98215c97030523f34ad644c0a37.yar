rule malware_lodeinfo_pdb
{
	meta:
		description = "LODEINFO malware"
		author = "JPCERT/CC Incident Response Group"
		hash1 = "b50d83820a5704522fee59164d7bc69bea5c834ebd9be7fd8ad35b040910807f"
		hash2 = "d1ed97ebeba07120ffaeef5e19f13d027ef4f4a3f45135f63b6715388b3cf49e"
		os = "windows"
		filetype = "executable"

	strings:
		$pdb1 = "E:\\Production\\Tool-Developing\\"
		$pdb2 = "E:\\Production\\Tool-Developing\\png_info\\Release\\png_info.pdb"
		$func1 = "displayAsciiArt"
		$func2 = "displayChunkNames"
		$func3 = "displayFilterTypes"
		$func4 = "displayPNGInfo"
		$func5 = "get_shellcode"
		$docCMG = "BBB975150319031903190319"

	condition:
		( all of ($pdb*) or all of ($func*)) and uint16(0)==0x5A4D or $docCMG
}

rule Carbanak_0915_1
{
	meta:
		description = "Carbanak Malware"
		author = "Florian Roth"
		reference = "https://www.csis.dk/en/csis/blog/4710/"
		date = "2015-09-03"
		score = 70
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "evict1.pdb" fullword ascii
		$s2 = "http://testing.corp 0" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 1 of them
}

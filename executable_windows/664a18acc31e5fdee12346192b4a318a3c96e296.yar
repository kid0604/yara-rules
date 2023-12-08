rule ms11080_withcmd
{
	meta:
		description = "Chinese Hacktool Set - file ms11080_withcmd.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "745e5058acff27b09cfd6169caf6e45097881a49"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Usage : ms11-080.exe cmd.exe Command " fullword ascii
		$s2 = "\\ms11080\\ms11080\\Debug\\ms11080.pdb" fullword ascii
		$s3 = "[>] by:Mer4en7y@90sec.org" fullword ascii
		$s4 = "[>] create porcess error" fullword ascii
		$s5 = "[>] ms11-080 Exploit" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and 1 of them
}

rule IISPutScannesr
{
	meta:
		description = "Chinese Hacktool Set - file IISPutScannesr.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "2dd8fee20df47fd4eed5a354817ce837752f6ae9"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "yoda & M.o.D." ascii
		$s2 = "-> come.to/f2f **************" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <500KB and all of them
}

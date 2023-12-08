rule cndcom_cndcom
{
	meta:
		description = "Chinese Hacktool Set - file cndcom.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "08bbe6312342b28b43201125bd8c518531de8082"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "- Rewritten by HDM last <hdm [at] metasploit.com>" fullword ascii
		$s2 = "- Usage: %s <Target ID> <Target IP>" fullword ascii
		$s3 = "- Remote DCOM RPC Buffer Overflow Exploit" fullword ascii
		$s4 = "- Warning:This Code is more like a dos tool!(Modify by pingker)" fullword ascii
		$s5 = "Windows NT SP6 (Chinese)" fullword ascii
		$s6 = "- Original code by FlashSky and Benjurry" fullword ascii
		$s7 = "\\C$\\123456111111111111111.doc" fullword wide
		$s8 = "shell3all.c" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 2 of them
}

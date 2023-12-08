rule HTTPSCANNER
{
	meta:
		description = "Chinese Hacktool Set - file HTTPSCANNER.EXE"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ae2929346944c1ea3411a4562e9d5e2f765d088a"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "HttpScanner.exe" fullword wide
		$s2 = "HttpScanner" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <3500KB and all of them
}

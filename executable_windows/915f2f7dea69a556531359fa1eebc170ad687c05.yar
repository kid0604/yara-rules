rule pw_inspector_2
{
	meta:
		description = "Chinese Hacktool Set - file pw-inspector.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e0a1117ee4a29bb4cf43e3a80fb9eaa63bb377bf"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Use for hacking: trim your dictionary file to the pw requirements of the target." fullword ascii
		$s2 = "Syntax: %s [-i FILE] [-o FILE] [-m MINLEN] [-M MAXLEN] [-c MINSETS] -l -u -n -p " ascii
		$s3 = "PW-Inspector" fullword ascii
		$s4 = "i:o:m:M:c:lunps" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 2 of them
}

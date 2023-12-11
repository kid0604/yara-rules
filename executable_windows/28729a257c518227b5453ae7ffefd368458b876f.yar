rule WAF_Bypass
{
	meta:
		description = "Chinese Hacktool Set - file WAF-Bypass.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "860a9d7aac2ce3a40ac54a4a0bd442c6b945fa4e"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Email: blacksplitn@gmail.com" fullword wide
		$s2 = "User-Agent:" fullword wide
		$s3 = "Send Failed.in RemoteThread" fullword ascii
		$s4 = "www.example.com" fullword wide
		$s5 = "Get Domain:%s IP Failed." fullword ascii
		$s6 = "Connect To Server Failed." fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <7992KB and 5 of them
}

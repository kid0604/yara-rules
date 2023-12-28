rule APT10_ChChes_strings
{
	meta:
		description = "ChChes malware"
		author = "JPCERT/CC Incident Response Group"
		hash = "7d515a46a7f4edfbae11837324f7c56b9a8164020e32aaaa3bef7d38763dd82d "
		os = "windows"
		filetype = "script"

	strings:
		$v1a = "/%r.html"
		$v1b = "http://"
		$v1c = "atan2"
		$v1d = "_hypot"
		$v1e = "_nextafter"
		$d1a = { 68 04 E1 00 00 }

	condition:
		all of them
}

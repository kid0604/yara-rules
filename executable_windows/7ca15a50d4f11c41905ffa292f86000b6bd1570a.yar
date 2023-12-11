import "pe"

rule LogPOS
{
	meta:
		author = "Morphick Security"
		description = "Detects Versions of LogPOS"
		md5 = "af13e7583ed1b27c4ae219e344a37e2b"
		os = "windows"
		filetype = "executable"

	strings:
		$mailslot = "\\\\.\\mailslot\\LogCC"
		$get = "GET /%s?encoding=%c&t=%c&cc=%I64d&process="
		$sc = {64 A1 30 00 00 00 8B 40 0C 8B 40 1C 8B 40 08 }

	condition:
		$sc and 1 of ($mailslot,$get)
}

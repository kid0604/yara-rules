rule INDICATOR_PDF_IPDropper
{
	meta:
		description = "Detects PDF documents with Action and URL pointing to direct IP address"
		author = "ditekSHen"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$s1 = { 54 79 70 65 20 2f 41 63 74 69 6f 6e 0d 0a 2f 53 20 2f 55 52 49 0d 0a }
		$s2 = /\/URI \(http(s)?:\/\/([0-9]{1,3}\.){3}[0-9]{1,3}\// ascii

	condition:
		uint32(0)==0x46445025 and all of them
}

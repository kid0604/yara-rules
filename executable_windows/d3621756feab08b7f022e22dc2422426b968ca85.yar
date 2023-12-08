rule winxml_dll
{
	meta:
		author = "@patrickrolsen"
		maltype = "Point of Sale (POS) Malware"
		reference = "ce0296e2d77ec3bb112e270fc260f274"
		version = "0.1"
		description = "Testing the base64 encoded file in sys32"
		date = "01/30/2014"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\system32\\winxml.dll"

	condition:
		uint16(0)==0x5A4D and ( all of ($s*))
}

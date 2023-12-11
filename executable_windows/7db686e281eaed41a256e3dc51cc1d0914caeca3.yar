rule Locky_alt_1
{
	meta:
		author = "kevoreilly"
		description = "Locky Payload"
		cape_type = "Locky Payload"
		os = "windows"
		filetype = "executable"

	strings:
		$string1 = "wallet.dat" wide
		$string2 = "Locky_recover" wide
		$string3 = "opt321" wide

	condition:
		uint16(0)==0x5A4D and all of them
}

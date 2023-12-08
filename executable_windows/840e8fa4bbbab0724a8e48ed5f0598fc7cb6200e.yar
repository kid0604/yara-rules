rule lacy_keylogger
{
	meta:
		author = "@patrickrolsen"
		reference = "Appears to be a form of keylogger."
		description = "Detects the presence of Lacy keylogger"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Lacy.exe" wide
		$s2 = "Bldg Chive Duel Rip Query" wide

	condition:
		uint16(0)==0x5A4D and all of ($s*)
}

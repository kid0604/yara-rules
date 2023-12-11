import "pe"

rule MALWARE_Win_Arkei
{
	meta:
		author = "ditekSHen"
		description = "Detect Arkei infostealer variants"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii wide
		$s2 = "/c taskkill /im " fullword ascii
		$s3 = "card_number_encrypted FROM credit_cards" ascii
		$s4 = "\\wallet.dat" ascii
		$s5 = "Arkei/" wide
		$s6 = "files\\passwords." ascii wide
		$s7 = "files\\cc_" ascii wide
		$s8 = "files\\autofill_" ascii wide
		$s9 = "files\\cookies_" ascii wide

	condition:
		uint16(0)==0x5a4d and all of them
}

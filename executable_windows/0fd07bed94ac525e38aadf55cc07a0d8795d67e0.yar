rule decoded_PolishBankRAT_fdsvc_strings
{
	meta:
		author = "Booz Allen Hamilton Dark Labs"
		description = "Finds hard coded strings in PolishBankRAT_fdsvc"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = "ssylka" wide ascii
		$str2 = "ustanavlivat" wide ascii
		$str3 = "poluchit" wide ascii
		$str4 = "pereslat" wide ascii
		$str5 = "derzhat" wide ascii
		$str6 = "vykhodit" wide ascii
		$str7 = "Nachalo" wide ascii

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and 4 of ($str*)
}

rule Atmos_Builder
{
	meta:
		description = "Generic signature for Hacktool.Atmos.Builder cracked version"
		author = "xylitol@temari.fr"
		reference = "http://www.xylibox.com/2016/02/citadel-0011-atmos.html"
		date = "20/08/2016"
		os = "windows"
		filetype = "executable"

	strings:
		$MZ = {4D 5A}
		$LKEY = "533D9226E4C1CE0A9815DBEB19235AE4" wide ascii
		$HWID = "D19FC0FB14BE23BCF35DA427951BB5AE" wide ascii
		$s1 = "url_loader=%S" wide ascii
		$s2 = "url_webinjects=%S" wide ascii
		$s3 = "url_tokenspy=%S" wide ascii
		$s4 = "file_webinjects=%S" wide ascii
		$s5 = "moneyparser.enabled=%u" wide ascii
		$s6 = "enable_luhn10_post=%u" wide ascii
		$s7 = "insidevm_enable=%u" wide ascii
		$s8 = "disable_antivirus=%u" wide ascii

	condition:
		$MZ at 0 and $LKEY and $HWID and all of ($s*)
}

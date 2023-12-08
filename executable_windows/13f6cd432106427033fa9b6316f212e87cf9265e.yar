rule INDICATOR_KB_GoBuildID_Hive
{
	meta:
		author = "ditekSHen"
		description = "Detects Golang Build IDs in Hive ransomware"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Go build ID: \"XDub7DGmWVQ2COC6W4If/XHMqRPf2lnJUiVkG1CR6/u_MaUU0go2UUmLb_INuv/WrZSyz-WMW1st_NaM935\"" ascii

	condition:
		uint16(0)==0x5a4d and 1 of them
}

import "pe"

rule WaterBug_wipbot_2013_core_PDF_alt_1
{
	meta:
		description = "Symantec Waterbug Attack - Trojan.Wipbot 2014 core PDF"
		author = "Symantec Security Response"
		date = "22.01.2015"
		reference = "http://t.co/rF35OaAXrl"
		os = "windows"
		filetype = "document"

	strings:
		$PDF = "%PDF-"
		$a = /\+[A-Za-z]{1}\. _ _ \$\+[A-Za-z]{1}\. _ \$ _ \+/
		$b = /\+[A-Za-z]{1}\.\$\$\$ _ \+/

	condition:
		($PDF at 0) and #a>150 and #b>200
}

rule WaterBug_wipbot_2013_core_PDF
{
	meta:
		description = "Symantec Waterbug Attack - Trojan.Wipbot 2014 core PDF"
		author = "Symantec Security Response"
		date = "22.01.2015"
		reference = "http://t.co/rF35OaAXrl"
		os = "windows"
		filetype = "document"

	strings:
		$a = /\+[A-Za-z]{1}\. _ _ \$\+[A-Za-z]{1}\. _ \$ _ \+/
		$b = /\+[A-Za-z]{1}\.\$\$\$ _ \+/

	condition:
		uint32(0)==0x46445025 and #a>150 and #b>200
}

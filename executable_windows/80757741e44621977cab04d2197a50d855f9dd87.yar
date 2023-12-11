rule Trickbot_alt_1
{
	meta:
		description = "detect TrickBot in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		hash1 = "2153be5c6f73f4816d90809febf4122a7b065cbfddaa4e2bf5935277341af34c"
		os = "windows"
		filetype = "executable"

	strings:
		$tagm1 = "<mcconf><ver>" wide
		$tagm2 = "</autorun></mcconf>" wide
		$tagc1 = "<moduleconfig><autostart>" wide
		$tagc2 = "</autoconf></moduleconfig>" wide
		$tagi1 = "<igroup><dinj>" wide
		$tagi2 = "</dinj></igroup>" wide
		$tags1 = "<servconf><expir>" wide
		$tags2 = "</plugins></servconf>" wide
		$tagl1 = "<slist><sinj>" wide
		$tagl2 = "</sinj></slist>" wide

	condition:
		all of ($tagm*) or all of ($tagc*) or all of ($tagi*) or all of ($tags*) or all of ($tagl*)
}

rule Windows_Trojan_Trickbot_46dc12dd
{
	meta:
		author = "Elastic Security"
		id = "46dc12dd-d81a-43a6-b7c3-f59afa1c863e"
		fingerprint = "997fe1c5a06bfffb754051436c48a0538ff2dcbfddf0d865c3a3797252247946"
		creation_date = "2021-03-29"
		last_modified = "2021-08-23"
		description = "Targets newBCtestDll64 module containing reverse shell functionality"
		threat_name = "Windows.Trojan.Trickbot"
		reference_sample = "BF38A787AEE5AFDCAB00B95CCDF036BC7F91F07151B4444B54165BB70D649CE5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "setconf" ascii fullword
		$a2 = "<moduleconfig><autostart>yes</autostart><sys>yes</sys><needinfo name = \"id\"/><needinfo name = \"ip\"/><autoconf><conf ctl = \""
		$a3 = "nf\" file = \"bcconfig\" period = \"90\"/></autoconf></moduleconfig>" ascii fullword
		$a4 = "<moduleconfig><autostart>yes</autostart><sys>yes</sys><needinfo name = \"id\"/><needinfo name = \"ip\"/><autoconf><conf ctl = \""
		$a5 = "<addr>" ascii fullword
		$a6 = "</addr>" ascii fullword

	condition:
		4 of ($a*)
}

rule FSO_s_zehir4_2
{
	meta:
		description = "Webshells Auto-generated - file zehir4.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "5b496a61363d304532bcf52ee21f5d55"
		os = "windows"
		filetype = "script"

	strings:
		$s4 = "\"Program Files\\Serv-u\\Serv"

	condition:
		all of them
}

rule WEB_INF_web : webshell
{
	meta:
		description = "Laudanum Injector Tools - file web.xml"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "0251baed0a16c451f9d67dddce04a45dc26cb4a3"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s1 = "<servlet-name>Command</servlet-name>" fullword ascii
		$s2 = "<jsp-file>/cmd.jsp</jsp-file>" fullword ascii

	condition:
		filesize <1KB and all of them
}

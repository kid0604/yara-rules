rule EXPL_JNDI_Exploit_Patterns_Dec21_1
{
	meta:
		description = "Detects JNDI Exploit Kit patterns in files"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/pimps/JNDI-Exploit-Kit"
		date = "2021-12-12"
		score = 60
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$x01 = "/Basic/Command/Base64/"
		$x02 = "/Basic/ReverseShell/"
		$x03 = "/Basic/TomcatMemshell"
		$x04 = "/Basic/JettyMemshell"
		$x05 = "/Basic/WeblogicMemshell"
		$x06 = "/Basic/JBossMemshell"
		$x07 = "/Basic/WebsphereMemshell"
		$x08 = "/Basic/SpringMemshell"
		$x09 = "/Deserialization/URLDNS/"
		$x10 = "/Deserialization/CommonsCollections1/Dnslog/"
		$x11 = "/Deserialization/CommonsCollections2/Command/Base64/"
		$x12 = "/Deserialization/CommonsBeanutils1/ReverseShell/"
		$x13 = "/Deserialization/Jre8u20/TomcatMemshell"
		$x14 = "/TomcatBypass/Dnslog/"
		$x15 = "/TomcatBypass/Command/"
		$x16 = "/TomcatBypass/ReverseShell/"
		$x17 = "/TomcatBypass/TomcatMemshell"
		$x18 = "/TomcatBypass/SpringMemshell"
		$x19 = "/GroovyBypass/Command/"
		$x20 = "/WebsphereBypass/Upload/"
		$fp1 = "<html"

	condition:
		1 of ($x*) and not 1 of ($fp*)
}

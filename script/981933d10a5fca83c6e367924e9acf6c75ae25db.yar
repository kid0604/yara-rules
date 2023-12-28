rule webshell_filesman_base64
{
	meta:
		description = "Webshell FilesMan"
		author = "JPCERT/CC Incident Response Group"
		hash = "01bd043b401144d60f09758eea5f2d13284f4fb682f8f99de032a84c4a0b6fe5"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$str1 = "IyEvdXNyL2Jpbi9wZXJsDQp1c2UgU29ja2V0Ow0KJGlhZGRyPWluZXRfYXRvbigkQVJHVlswXSkgfHwgZGllKCJFcnJvcjogJCFcbiIpOw0KJHBhZGRyPXNvY2thZGRy"
		$str2 = "IyEvdXNyL2Jpbi9wZXJsDQokU0hFTEw9Ii9iaW4vc2ggLWkiOw0KaWYgKEBBUkdWIDwgMSkgeyBleGl0KDEpOyB9DQp1c2UgU29ja2V0Ow0Kc29ja2V0KFMsJlBGX0"

	condition:
		uint32(0)==0x68703F3C and all of them
}

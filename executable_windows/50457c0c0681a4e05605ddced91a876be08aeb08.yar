rule Lazarus_obfuscate_string
{
	meta:
		description = "Strings contained in obfuscated files used by Lazarus"
		author = "JPCERT/CC Incident Response Group"
		hash = "e5466b99c1af9fe3fefdd4da1e798786a821c6d853a320d16cc10c06bc6f3fc5"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = { 2D 41 72 67 75 6D 65 6E 74 4C 69 73 74 20 27 5C 22 00 }
		$str2 = "%^&|," wide
		$str3 = "SeDebugPrivilege" wide

	condition:
		uint16(0)==0x5a4d and filesize >1MB and all of them
}

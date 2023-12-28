rule WaterPamola_webshell_str
{
	meta:
		description = "Chainese webshell using water pamola"
		author = "JPCERT/CC Incident Response Group"
		hash = "a619f1ff0c6a5c8fc26871b9c0492ca331a9f84c66fa7479d0069b7e3b22ba31"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$str1 = "$password"
		$str2 = "$register_key"
		$str3 = "$check_copyright"
		$str4 = "$global_version"
		$str5 = "Language and charset conversion settings"
		$str6 = "This is a necessary key"

	condition:
		uint32(0)==0x68703F3C and all of them
}

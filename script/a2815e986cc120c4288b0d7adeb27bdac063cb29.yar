rule WaterPamola_includewebshell_php
{
	meta:
		description = "Include only_pcd webshell in Water Pamola"
		author = "JPCERT/CC Incident Response Group"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$func1 = "@INCLUDE_ONCE($_FILES['only_pcd']['tmp_name']);"

	condition:
		uint32(0)==0x68703F3C and all of them
}

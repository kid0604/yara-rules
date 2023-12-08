rule z_webshell
{
	meta:
		description = "Detection for the z_webshell"
		author = "DHS NCCIC Hunt and Incident Response Team"
		date = "2018/01/25"
		md5 = "2C9095C965A55EFC46E16B86F9B7D6C6"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$webshell_name = "public string z_progname =" nocase ascii wide
		$webshell_password = "public string Password =" nocase ascii wide

	condition:
		( uint32(0)==0x2040253c or uint32(0)==0x7073613c) and filesize <100KB and 2 of ($webshell_*)
}

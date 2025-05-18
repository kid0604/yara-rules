import "pe"

rule INDICATOR_TOOL_SharpSQLPwn
{
	meta:
		author = "ditekshen"
		description = "Detects SharpSQLPwn"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "smb_ip" fullword ascii
		$s2 = "Recon" fullword ascii
		$s3 = "UNCPathInjection" fullword ascii
		$s4 = "from sys.server_principals" wide
		$s5 = "EXEC sp_configure '" wide
		$s6 = "EXEC ('sp_configure" wide
		$s7 = "CREATE ASSEMBLY" wide
		$s8 = "DROP ASSEMBLY" wide
		$s9 = "FROM 0x" wide
		$s10 = "EXEC master..xp_dirtree \"\\\\" wide

	condition:
		uint16(0)==0x5a4d and 7 of them
}

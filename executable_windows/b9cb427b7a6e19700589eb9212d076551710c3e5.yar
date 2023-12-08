rule INDICATOR_TOOL_PWS_SharpWeb
{
	meta:
		author = "ditekSHen"
		description = "detects all versions of the browser password dumping .NET tool, SharpWeb."
		os = "windows"
		filetype = "executable"

	strings:
		$param1 = "logins" nocase wide
		$param2 = "cookies" nocase wide
		$param3 = "edge" nocase wide
		$param4 = "firefox" nocase wide
		$param5 = "chrome" nocase wide
		$path1 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" wide
		$path2 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\" wide
		$path3 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies" wide
		$path4 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Bookmarks" wide
		$sql1 = "UPDATE sqlite_temp_master SET sql = sqlite_rename_trigger(sql, %Q), tbl_name = %Q WHERE %s;" nocase wide
		$sql2 = "UPDATE %Q.%s SET type='%s', name=%Q, tbl_name=%Q, rootpage=#%d, sql=%Q WHERE rowid=#%d" nocase wide
		$sql3 = "SELECT action_url, username_value, password_value FROM logins" nocase wide
		$func1 = "get_encryptedPassword" fullword ascii
		$func2 = "<GetLogins>g__GetVaultElementValue0_0" fullword ascii
		$func3 = "<encryptedPassword>k__BackingField" fullword ascii
		$pdb = "\\SharpWeb\\obj\\Debug\\SharpWeb.pdb" fullword ascii

	condition:
		uint16(0)==0x5a4d and ((1 of ($func*) and 3 of ($param*) and (1 of ($path*) or 1 of ($sql*))) or $pdb)
}

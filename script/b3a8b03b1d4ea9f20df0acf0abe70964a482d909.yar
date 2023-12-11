rule mysql_database_presence
{
	meta:
		author = "CYB3RMX"
		description = "This rule checks MySQL database presence"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$db = "MySql.Data"
		$db1 = "MySqlCommand"
		$db2 = "MySqlConnection"
		$db3 = "MySqlDataReader"
		$db4 = "MySql.Data.MySqlClient"

	condition:
		( any of ($db*))
}

rule Lazarus_keylogger_str
{
	meta:
		description = "Keylogger in Lazarus"
		author = "JPCERT/CC Incident Response Group"
		hash = "e0567863b10e9b1ac805292d30626ea24b28ee12f3682a93d29120db3b77a40a"
		os = "windows"
		filetype = "executable"

	strings:
		$mutex = "c2hvcGxpZnRlcg"
		$path = "%APPDATA%\\\\Microsoft\\\\Camio\\\\"
		$str = "[%02d/%02d/%d %02d:%02d:%02d]"
		$table1 = "CppSQLite3Exception"
		$table2 = "CppSQLite3Query"
		$table3 = "CppSQLite3DB"
		$table4 = "CDataLog"
		$table5 = "CKeyLogger"

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3c))==0x00004550 and 4 of them
}

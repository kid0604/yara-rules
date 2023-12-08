rule APT_MAL_LUA_Hunting_Lua_SEASPRAY_1
{
	meta:
		author = "Mandiant"
		date = "2023-06-15"
		reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
		description = "Hunting rule looking for strings observed in SEASPRAY samples."
		hash = "35cf6faf442d325961935f660e2ab5a0"
		score = 70
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$str1 = "string.find(attachment:filename(),'obt075') ~= nil"
		$str2 = "os.execute('cp '..tostring(tmpfile)..' /tmp/'..attachment:filename())"
		$str3 = "os.execute('rverify'..' /tmp/'..attachment:filename())"

	condition:
		all of them
}

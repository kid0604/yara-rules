rule APT_MAL_LUA_Hunting_Lua_SKIPJACK_2
{
	meta:
		author = "Mandiant"
		date = "2023-06-15"
		reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
		description = "Hunting rule looking for strings observed in SKIPJACK samples."
		hash = "87847445f9524671022d70f2a812728f"
		score = 70
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$str1 = "hdr:name() == 'Content-ID'"
		$str2 = "hdr:body() ~= nil"
		$str3 = "string.match(hdr:body(),\"^[%w%+/=\\r\\n]+$\")"
		$str4 = "openssl aes-256-cbc"
		$str5 = "| base64 -d| sh 2>"

	condition:
		all of them
}

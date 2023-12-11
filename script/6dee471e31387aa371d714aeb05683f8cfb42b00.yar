rule APT_MAL_LUA_Hunting_SKIPJACK_1
{
	meta:
		author = "Mandiant"
		date = "2023-06-15"
		reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
		description = "Hunting rule looking for strings observed in SKIPJACK installation script."
		hash = "e4e86c273a2b67a605f5d4686783e0cc"
		score = 70
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$str1 = "hdr:name() == 'Content-ID'" base64
		$str2 = "hdr:body() ~= nil" base64
		$str3 = "string.match(hdr:body(),\"^[%w%+/=\\r\\n]+$\")" base64
		$str4 = "openssl aes-256-cbc" base64
		$str5 = "mod_content.lua"
		$str6 = "#!/bin/sh"

	condition:
		all of them
}

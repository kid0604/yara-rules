rule md5_fb9e35bf367a106d18eb6aa0fe406437
{
	meta:
		description = "Detects file with specific MD5 hash"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "0B6KVua7D2SLCNDN2RW1ORmhZRWs/sp_tilang.js"

	condition:
		any of them
}

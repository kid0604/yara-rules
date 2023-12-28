rule CryptHunter_httpbotjs_str
{
	meta:
		description = "HTTP bot js in CryptHunter"
		author = "JPCERT/CC Incident Response Group"
		hash1 = "b316b81bc0b0deb81da5e218b85ca83d7260cc40dae97766bc94a6931707dc1b"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$base64 = "W0NtZGxldEJpbmRpbmcoKV1QYXJhbShbUGFyYW1ldGVyKFBvc2l0aW9uPTApXVtTdHJpbmddJFVSTCxbUGFyYW1ldGVyKFBvc2l0aW9uPTEpXVtTdHJpbmddJFVJRCkNCmZ1bmN0aW9uIEh0dHBSZXEyew" ascii
		$var1 = { 40 28 27 22 2b 70 32 61 2b 22 27 2c 20 27 22 2b 75 69 64 2b 22 27 29 3b 7d }

	condition:
		all of them
}

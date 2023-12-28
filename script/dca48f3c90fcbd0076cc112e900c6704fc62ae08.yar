rule cve202120837_webshell_HelloDolly
{
	meta:
		description = "CVE-2021-20837 PHP webshell (fake Hello Dolly)"
		author = "JPCERT/CC Incident Response Group"
		hash = "776264178e8534b6404e649e0256e5467639b14e2bf2c778c6b25dc944dee211"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$str1 = "data:image/png;ZXJyb3JfcmVwb3J0a"
		$str2 = "\\x63\\x72\\x65\\x61\\x74\\x65\\x5f\\x66\\x75\\x6e\\x63\\x74\\x69\\x6f\\x6e"
		$str3 = { 3C 46 69 6C 65 73 4D 61 74 63 68 20 5C 22 2E 28 70 68 7C 70 68 74 6D 6C 7C 70 68 70 29 5C 24 5C 22 3E 5C 6E 20 4F 72 64 65 72 20 61 6C 6C 6F 77 2C 64 65 6E 79 5C 6E 20 41 6C 6C 6F 77 20 66 72 6F 6D 20 61 6C 6C 5C 6E 3C 2F 46 69 6C 65 73 4D 61 74 63 68 3E }
		$str4 = { 23 3C 69 6D 67 20 73 72 63 3D 22 64 61 74 61 3A 69 6D 61 67 65 2F 70 6E 67 3B 28 2E 2A 29 22 3E 23 }

	condition:
		uint32(0)==0x68703F3C and 2 of ($str*)
}

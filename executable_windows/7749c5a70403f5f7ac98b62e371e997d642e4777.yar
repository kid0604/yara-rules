rule APT_HKTL_Proxy_Tool_Jun23_1
{
	meta:
		description = "Detects agent used as proxy tool in UNC4841 intrusions - possibly Alchemist C2 framework implant"
		author = "Florian Roth"
		reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
		date = "2023-06-16"
		score = 75
		hash1 = "ca72fa64ed0a9c22d341a557c6e7c1b6a7264b0c4de0b6f717dd44bddf550bca"
		hash2 = "57e4b180fd559f15b59c43fb3335bd59435d4d76c4676e51a06c6b257ce67fb2"
		os = "windows"
		filetype = "executable"

	strings:
		$a2 = "/src/runtime/panic.go"
		$s1 = "main.handleClientRequest" ascii fullword
		$s2 = "main.sockIP.toAddr" ascii fullword

	condition:
		( uint16(0)==0x5a4d or uint32be(0)==0x7f454c46 or uint16(0)==0xfeca or uint16(0)==0xfacf or uint32(0)==0xbebafeca or uint32(0)==0xbebafeca) and filesize <10MB and all of them
}

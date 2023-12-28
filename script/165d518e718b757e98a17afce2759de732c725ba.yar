rule CryptHunter_jsDownloader
{
	meta:
		description = "1st stage js downloader in Dangerouspassword"
		author = "JPCERT/CC Incident Response Group"
		hash1 = "67a0f25a20954a353021bbdfdd531f7cc99c305c25fb03079f7abbc60e8a8081"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$code01 = "UID + AgentType + SessionType + OS;" ascii wide fullword
		$code02 = "received_data.toString().startsWith" ascii wide fullword
		$str01 = "GITHUB_RES" ascii wide fullword
		$str02 = "GITHUB_REQ" ascii wide fullword

	condition:
		( filesize >1KB) and ( filesize <5MB) and (1 of ($code*) or (2 of ($str*)))
}

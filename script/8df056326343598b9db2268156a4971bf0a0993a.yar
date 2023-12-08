rule APT_Sandworm_InitFile_May20_1
{
	meta:
		description = "Detects mysql init script used by Sandworm on compromised machines"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
		date = "2020-05-28"
		hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
		hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s1 = "GRANT ALL PRIVILEGES ON * . * TO 'mysqldb'@'localhost';" ascii
		$s2 = "CREATE USER 'mysqldb'@'localhost' IDENTIFIED BY '" ascii fullword

	condition:
		filesize <10KB and all of them
}

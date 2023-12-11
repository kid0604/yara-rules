import "pe"

rule Wanna_Sample_84c82835a5d21bbcf75a61706d8ab549 : Wanna_Sample_84c82835a5d21bbcf75a61706d8ab549
{
	meta:
		description = "Specific sample match for WannaCryptor"
		MD5 = "84c82835a5d21bbcf75a61706d8ab549"
		SHA1 = "5ff465afaabcbf0150d1a3ab2c2e74f3a4426467"
		SHA256 = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
		INFO = "Looks for 'taskdl' and 'taskse' at known offsets"
		os = "windows"
		filetype = "executable"

	strings:
		$taskdl = { 00 74 61 73 6b 64 6c }
		$taskse = { 00 74 61 73 6b 73 65 }

	condition:
		$taskdl at 3419456 and $taskse at 3422953
}

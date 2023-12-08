import "pe"

rule APT_ME_BigBang_Mal_Jul18_1
{
	meta:
		description = "Detects malware from Big Bang report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://research.checkpoint.com/apt-attack-middle-east-big-bang/"
		date = "2018-07-09"
		hash1 = "ac6462e9e26362f711783b9874d46fefce198c4c3ca947a5d4df7842a6c51224"
		hash2 = "e1f52ea30d25289f7a4a5c9d15be97c8a4dfe10eb68ac9d031edcc7275c23dbc"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "%Y%m%d-%I-%M-%S" fullword ascii
		$s2 = "/api/serv/requests/%s/runfile/delete" fullword ascii
		$s3 = "\\part.txt" ascii
		$s4 = "\\ALL.txt" ascii
		$s5 = "\\sat.txt" ascii
		$s6 = "runfile.proccess_name" fullword ascii
		$s7 = "%s%s%p%s%zd%s%d%s%s%s%s%s" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and 4 of them
}

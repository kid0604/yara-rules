import "pe"

rule Crackmapexec_EXE
{
	meta:
		description = "Detects CrackMapExec hack tool"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-04-06"
		score = 85
		hash1 = "371f104b7876b9080c519510879235f36edb6668097de475949b84ab72ee9a9a"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "core.scripts.secretsdump(" ascii
		$s2 = "core.scripts.samrdump(" ascii
		$s3 = "core.uacdump(" ascii

	condition:
		uint16(0)==0x5a4d and filesize <10000KB and 2 of them
}

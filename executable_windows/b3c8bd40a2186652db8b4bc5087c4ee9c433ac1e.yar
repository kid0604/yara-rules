import "pe"

rule Suckfly_Nidiran_Gen_1
{
	meta:
		description = "Detects Suckfly Nidiran Trojan"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.symantec.com/connect/blogs/suckfly-revealing-secret-life-your-code-signing-certificates"
		date = "2018-01-28"
		hash1 = "ac7d7c676f58ebfa5def9b84553f00f283c61e4a310459178ea9e7164004e734"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "WriteProcessMemory fail at %d " fullword ascii
		$s2 = "CreateRemoteThread fail at %d " fullword ascii
		$s3 = "CreateRemoteThread Succ" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and 2 of them
}

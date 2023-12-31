rule malware_INetGet_rtf
{
	meta:
		description = "APT Malware using INetGet"
		author = "JPCERT/CC Incident Response Group"
		hash = "4b366ea3c86fbf8846fa96381d2d267901af436441594a009b76d133a70404f1"
		os = "windows"
		filetype = "document"

	strings:
		$v1c = "7a337d33563347337433563347331d3356334b3356"
		$v1d = {7B 5C 72 74 5C 61 6E 73 69}

	condition:
		all of them
}

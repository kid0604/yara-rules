rule Lazarus_ValeforBeta_strings
{
	meta:
		description = "ValeforBeta malware in Lazarus"
		author = "JPCERT/CC Incident Response Group"
		hash1 = "5f3353063153a29c8c3075ffb1424b861444a091d9007e6f3b448ceae5a3f02e"
		os = "windows"
		filetype = "script"

	strings:
		$str0 = "cmd interval: %d->%d" ascii wide
		$str1 = "script interval: %d->%d" ascii wide
		$str2 = "Command not exist. Try again." ascii wide
		$str3 = "successfully uploaded from %s to %s" ascii wide
		$str4 = "success download from %s to %s" ascii wide
		$str5 = "failed with error code: %d" ascii wide

	condition:
		3 of ($str*)
}

rule Lazarus_httpbot_jsessid
{
	meta:
		description = "Unknown HTTP bot in Lazarus"
		author = "JPCERT/CC Incident Response Group"
		hash1 = "451ad26a41a8b8ae82ccfc850d67b12289693b227a7114121888b444d72d4727"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$jsessid = "jsessid=%08x%08x%08x" ascii
		$http = "%04x%04x%04x%04x" ascii
		$init = { 51 68 ?? ?? ?? 00 51 BA 04 01 00 00 B9 ?? ?? ?? 00 E8 }
		$command = { 8B ?? ?? 05 69 62 2B 9F 83 F8 1D 0F ?? ?? ?? 00 00 FF}

	condition:
		$command or ($jsessid and $http and #init>=3)
}

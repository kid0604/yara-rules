rule Nanocore_alt_1
{
	meta:
		description = "detect Nanocore in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		reference = "internal research"
		os = "windows"
		filetype = "executable"

	strings:
		$v1 = "NanoCore Client"
		$v2 = "PluginCommand"
		$v3 = "CommandType"

	condition:
		all of them
}

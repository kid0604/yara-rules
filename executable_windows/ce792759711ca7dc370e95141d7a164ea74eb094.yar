rule DragonOK_CHWRITER_strings
{
	meta:
		description = "CHWRITER malware"
		author = "JPCERT/CC Incident Response Group"
		hash = "fb1ee331be22267bc74db1c42ebb8eb8029c87f6d7a74993127db5d7ffdceaf4"
		os = "windows"
		filetype = "executable"

	strings:
		$command = "%s a a b c %d \"%s\"" wide

	condition:
		$command
}

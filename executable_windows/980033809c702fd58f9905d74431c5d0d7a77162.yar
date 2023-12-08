rule DestructiveTargetCleaningTool3
{
	meta:
		description = "Detects a destructive target cleaning tool based on specific command line arguments"
		os = "windows"
		filetype = "executable"

	strings:
		$S1_CMD_Arg = "/install" fullword
		$S2_CMD_Parse = "\"%s\"  /install \"%s\"" fullword
		$S3_CMD_Builder = "\"%s\"  \"%s\" \"%s\" %s" fullword

	condition:
		all of them
}

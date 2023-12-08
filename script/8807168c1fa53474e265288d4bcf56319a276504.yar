rule DestructiveTargetCleaningTool4
{
	meta:
		description = "Detects a destructive batch script used for cleaning purposes"
		os = "windows"
		filetype = "script"

	strings:
		$BATCH_SCRIPT_LN1_0 = "goto x" fullword
		$BATCH_SCRIPT_LN1_1 = "del" fullword
		$BATCH_SCRIPT_LN2_0 = "if exist" fullword
		$BATCH_SCRIPT_LN3_0 = ":x" fullword
		$BATCH_SCRIPT_LN4_0 = "zz%d.bat" fullword

	condition:
		(#BATCH_SCRIPT_LN1_1==2) and all of them
}

rule AutoIT_compiled_script
{
	meta:
		description = "Is an AutoIT compiled script"
		author = "Ivan Kwiatkowski (@JusticeRage)"
		os = "windows"
		filetype = "script"

	strings:
		$a0 = "AutoIt Error" ascii wide
		$a1 = "reserved for AutoIt internal use" ascii wide

	condition:
		any of them
}

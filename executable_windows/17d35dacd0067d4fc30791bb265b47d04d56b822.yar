rule Trojan_Win32_PlaKeylog_B
{
	meta:
		author = "Microsoft"
		description = "Keylogger component"
		original_sample_sha1 = "0096a3e0c97b85ca75164f48230ae530c94a2b77"
		unpacked_sample_sha1 = "6a1412daaa9bdc553689537df0a004d44f8a45fd"
		activity_group = "Platinum"
		version = "1.0"
		last_modified = "2016-04-12"
		os = "windows"
		filetype = "executable"

	strings:
		$hook = {C6 06 FF 46 C6 06 25}
		$dasm_engine = {80 C9 10 88 0E 8A CA 80 E1 07 43 88 56 03 80 F9 05}

	condition:
		$hook and $dasm_engine
}

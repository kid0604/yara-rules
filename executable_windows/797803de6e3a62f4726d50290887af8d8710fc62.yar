rule win_redline_payload_dec_2023
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/12/24"
		description = "Patterns observed in redline"
		sha_256 = "5790aead07ce0b9b508392b9a2f363ef77055ae16c44231773849c87a1dd15a4"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = {16 72 ?? ?? ?? 70 A2 7E ?? ?? ?? 04 17 72 ?? ?? ?? 70 7E ?? ?? ?? 04 16 9A 28 ?? ?? ?? 06 A2 7E ?? ?? ?? 04 18 72 ?? ?? ?? 70 }

	condition:
		all of them
}

rule win_cobalt_strike_loader_shellcode_jun_2023
{
	meta:
		author = "Matthew @ Embee_research"
		vendor = ""
		created = "2023/06/31"
		description = "Detection of an encoder observed with Cobalt Strike shellcode"
		os = "windows"
		filetype = "executable"

	strings:
		$get_enc_offset = {8b 88 c0 00 00 00 8b 90 c4 00 00 00 48 8d b0 c8 00 00 00}
		$decode_loop = {ac 83 e1 03 d2 c8 ff c1 aa ff ca 75 f3}
		$b64_initial_bytes = "SInISIlMJAiLiMAAAACLkMQAAABIjbDIAAAA" wide ascii

	condition:
		(($get_enc_offset and $decode_loop) or $b64_initial_bytes) and filesize <10000KB
}

rule crime_win32_parallax_payload_1
{
	meta:
		description = "Detects Parallax Injected Payload v1.01"
		author = "@VK_Intel"
		reference = "https://twitter.com/VK_Intel/status/1227976106227224578"
		date = "2020-02-24"
		hash1 = "20d0be64a0e0c2e96729143d41b334603f5d3af3838a458b0627af390ae33fbc"
		os = "windows"
		filetype = "executable"

	strings:
		$zwdelay_prologue = { 66 ?? ?? ?? 66 83 c1 01 66 ?? ?? ?? 50 b8 cb cb cb cb 89 ?? ?? ?? ?? ?? 58 8b ?? ?? ?? ?? ?? 89 ?? ?? 68 88 13 00 00 8b ?? ?? 8b ?? ?? 51 e8 ?? ?? ?? ??}
		$wininet_call = { b8 77 00 00 00 66 ?? ?? ?? b9 69 00 00 00 66 ?? ?? ?? ba 6e 00 00 00 66 ?? ?? ?? b8 69 00 00 00 66 ?? ?? ?? b9 6e 00 00 00 66 ?? ?? ?? ba 65 00 00 00 66 ?? ?? ?? b8 74 00 00 00 66 ?? ?? ?? 33 c9 66 ?? ?? ?? 8d ?? ?? 52 8b ?? ?? 8b ?? ?? ff d1 89 ?? ?? 6a 00 68 0c fc e5 f2 8b ?? ?? 52 e8 ?? ?? ?? ?? 83 c4 0c 89 ?? ?? 6a 00 68 3d a8 16 da 8b ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 0c 89 ?? ?? 6a 00 68 e0 05 65 01 8b ?? ?? 51 e8 ?? ?? ?? ?? 83 c4 0c 89 ?? ?? 6a 00 68 f5 98 c0 6c 8b ?? ?? 52 e8 ?? ?? ?? ?? 83 c4 0c 89 ?? ?? 6a 00 68 24 1d 19 e5 8b ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 0c 89 ?? ?? 6a 00 68 a8 ed f2 ce 8b ?? ?? 8b ?? ?? 52 e8 ?? ?? ?? ?? 83 c4 0c 89 ?? ?? 6a 00 6a 00 ff ?? ?? 85 c0 75 ?? 68 88 13 00 00 ff ?? ?? eb ?? 6a 00 68 00 01 00 04 6a }
		$rand_png_call = { b8 25 00 00 00 66 ?? ?? ?? ?? ?? ?? b9 78 00 00 00 66 ?? ?? ?? ?? ?? ?? ba 2e 00 00 00 66 ?? ?? ?? ?? ?? ?? b8 70 00 00 00 66 ?? ?? ?? ?? ?? ?? b9 6e 00 00 00 66 ?? ?? ?? ?? ?? ?? ba 67 00 00 00 66 ?? ?? ?? ?? ?? ?? 33 c0 66 ?? ?? ?? ?? ?? ?? 6a 64 6a 40 8b ?? ?? 8b ?? ?? ff d2 89 ?? ?? 8b ?? ?? 50 68 00 e1 f5 05 68 10 27 00 00 e8 ?? ?? ?? ??}

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 2 of them
}

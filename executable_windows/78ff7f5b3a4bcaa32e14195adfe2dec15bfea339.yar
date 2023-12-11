rule mimikatz_alt_1
{
	meta:
		description = "mimikatz"
		author = "Benjamin DELPY (gentilkiwi)"
		tool_author = "Benjamin DELPY (gentilkiwi)"
		score = 80
		os = "windows"
		filetype = "executable"

	strings:
		$exe_x86_1 = { 89 71 04 89 [0-3] 30 8d 04 bd }
		$exe_x86_2 = { 89 79 04 89 [0-3] 38 8d 04 b5 }
		$exe_x64_1 = { 4c 03 d8 49 [0-3] 8b 03 48 89 }
		$exe_x64_2 = { 4c 8b df 49 [0-3] c1 e3 04 48 [0-3] 8b cb 4c 03 [0-3] d8 }
		$dll_1 = { c7 0? 00 00 01 00 [4-14] c7 0? 01 00 00 00 }
		$dll_2 = { c7 0? 10 02 00 00 ?? 89 4? }
		$sys_x86 = { a0 00 00 00 24 02 00 00 40 00 00 00 [0-4] b8 00 00 00 6c 02 00 00 40 00 00 00 }
		$sys_x64 = { 88 01 00 00 3c 04 00 00 40 00 00 00 [0-4] e8 02 00 00 f8 02 00 00 40 00 00 00 }

	condition:
		( all of ($exe_x86_*)) or ( all of ($exe_x64_*)) or ( all of ($dll_*)) or ( any of ($sys_*))
}

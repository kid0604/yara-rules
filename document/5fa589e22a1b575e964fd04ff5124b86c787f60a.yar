rule maldoc_find_kernel32_base_method_1 : maldoc
{
	meta:
		author = "Didier Stevens (https://DidierStevens.com)"
		description = "Detects maldoc using the kernel32 base method 1"
		os = "windows"
		filetype = "document"

	strings:
		$a1 = {64 8B (05|0D|15|1D|25|2D|35|3D) 30 00 00 00}
		$a2 = {64 A1 30 00 00 00}

	condition:
		any of them
}

rule GuloaderPrecursor
{
	meta:
		author = "kevoreilly"
		description = "Guloader precursor"
		cape_options = "bp0=$antidbg,action0=scan,hc0=1,count=0"
		os = "windows"
		filetype = "executable"

	strings:
		$antidbg = {39 48 04 (0F 85 [3] ??|75 ??) 39 48 08 (0F 85 [3] ??|75 ??) 39 48 0C (0F 85 [3] ??|75 ??)}
		$except = {8B 45 08 [0-3] 8B 00 [0-3] 8B 58 18 [0-20] 81 38 05 00 00 C0 0F 85 [4-7] 83 FB 00 (0F 84|74)}

	condition:
		2 of them and not uint16(0)==0x5A4D
}

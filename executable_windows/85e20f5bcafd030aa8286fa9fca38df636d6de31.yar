rule Amplia_Security_Tool
{
	meta:
		description = "Amplia Security Tool"
		score = 60
		nodeepdive = 1
		os = "windows"
		filetype = "executable"

	strings:
		$a = "Amplia Security"
		$b = "Hernan Ochoa"
		$c = "getlsasrvaddr.exe"
		$d = "Cannot get PID of LSASS.EXE"
		$e = "extract the TGT session key"
		$f = "PPWDUMP_DATA"

	condition:
		1 of them
}

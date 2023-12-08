rule MockDll_Gen
{
	meta:
		description = "Detects MockDll - regsvr DLL loader"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/MZ7dRg"
		date = "2017-10-18"
		hash1 = "bfc5c6817ff2cc4f3cd40f649e10cc9ae1e52139f35fdddbd32cb4d221368922"
		hash2 = "80b931ab1798d7d8a8d63411861cee07e31bb9a68f595f579e11d3817cfc4aca"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "mock_run_ini_Win32.dll" fullword ascii
		$x2 = "mock_run_ini_x64.dll" fullword ascii
		$s1 = "RealCmd=%s %s" fullword ascii
		$s2 = "MockModule=%s" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <20KB and (1 of ($x*) or 2 of them )
}

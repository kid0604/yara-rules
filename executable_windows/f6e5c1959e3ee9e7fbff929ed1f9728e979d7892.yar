rule Regin_sig_svcsstat
{
	meta:
		description = "Detects svcstat from Regin report - file svcsstat.exe_sample"
		author = "@MalwrSignatures"
		date = "26.11.14"
		hash = "5164edc1d54f10b7cb00a266a1b52c623ab005e2"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Service Control Manager" fullword ascii
		$s1 = "_vsnwprintf" ascii
		$s2 = "Root Agency" fullword ascii
		$s3 = "Root Agency0" fullword ascii
		$s4 = "StartServiceCtrlDispatcherA" fullword ascii
		$s5 = "\\\\?\\UNC" fullword wide
		$s6 = "%ls%ls" fullword wide

	condition:
		all of them and filesize <15KB and filesize >10KB
}

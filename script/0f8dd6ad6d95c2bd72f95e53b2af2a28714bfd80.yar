rule Empire_Out_Minidump
{
	meta:
		description = "Detects Empire component - file Out-Minidump.ps1"
		author = "Florian Roth"
		reference = "https://github.com/adaptivethreat/Empire"
		date = "2016-11-05"
		hash1 = "7803ae7ba5d4e7d38e73745b3f321c2ca714f3141699d984322fa92e0ff037a1"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "$Result = $MiniDumpWriteDump.Invoke($null, @($ProcessHandle," fullword ascii
		$s2 = "$ProcessFileName = \"$($ProcessName)_$($ProcessId).dmp\"" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <10KB and 1 of them ) or all of them
}

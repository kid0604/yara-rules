rule Malware_QA_vqgk
{
	meta:
		description = "VT Research QA uploaded malware - file vqgk.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "VT Research QA"
		date = "2016-08-29"
		modified = "2022-12-21"
		score = 80
		hash1 = "99541ab28fc3328e25723607df4b0d9ea0a1af31b58e2da07eff9f15c4e6565c"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Z:\\devcenter\\aggressor\\external" ascii
		$x2 = "\\beacon\\Release\\beacon.pdb" ascii
		$x3 = "%d is an x86 process (can't inject x64 content)" fullword ascii
		$x4 = "%d is an x64 process (can't inject x86 content)" fullword ascii
		$s1 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword ascii
		$s2 = "Could not open process token: %d (%u)" fullword ascii
		$s3 = "\\\\%s\\pipe\\msagent_%x" fullword ascii
		$s4 = "\\sysnative\\rundll32.exe" ascii
		$s5 = "Failed to impersonate logged on user %d (%u)" fullword ascii
		$s6 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" fullword ascii
		$s7 = "could not write to process memory: %d" fullword ascii
		$s8 = "beacon.dll" fullword ascii
		$s9 = "Failed to impersonate token from %d (%u)" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <600KB and (1 of ($x*) or 5 of ($s*))) or (7 of them )
}

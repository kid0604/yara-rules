import "math"
import "pe"

private rule cobaltstrike_beacon_raw
{
	meta:
		description = "Detects raw Cobalt Strike beacon indicators in files"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "%d is an x64 process (can't inject x86 content)" fullword
		$s2 = "Failed to impersonate logged on user %d (%u)" fullword
		$s3 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword
		$s4 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" fullword
		$s5 = "could not run command (w/ token) because of its length of %d bytes!" fullword
		$s6 = "could not write to process memory: %d" fullword
		$s7 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" fullword
		$s8 = "Could not connect to pipe (%s): %d" fullword
		$b1 = "beacon.dll" fullword
		$b2 = "beacon.x86.dll" fullword
		$b3 = "beacon.x64.dll" fullword

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and ( any of ($b*) or 5 of ($s*))
}

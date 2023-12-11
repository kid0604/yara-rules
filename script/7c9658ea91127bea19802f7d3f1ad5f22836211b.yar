import "math"
import "pe"

rule hacktool_windows_cobaltstrike_in_memory
{
	meta:
		description = "Detect the risk of  Malware Cobalt Strike Rule 11"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s"
		$s2 = "powershell -nop -exec bypass -EncodedCommand \"%s\""
		$s3 = "%d is an x86 process (can't inject x64 content)"
		$s4 = "%d.%d    %s  %s  %s  %s"
		$s5 = "could not upload file: %d"
		$s7 = "KVK...................................0.-.n"
		$s8 = "%d is an x64 process (can't inject x86 content)"
		$op1 = {C7 45 F0 0? 00 00 00 E9 BF A3 BC FF}

	condition:
		6 of them
}

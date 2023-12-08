import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_WMI_EnumerateVideoDevice
{
	meta:
		author = "ditekSHen"
		description = "Detects executables attemping to enumerate video devices using WMI"
		os = "windows"
		filetype = "executable"

	strings:
		$q1 = "Select * from Win32_CacheMemory" ascii wide nocase
		$d1 = "{860BB310-5D01-11d0-BD3B-00A0C911CE86}" ascii wide
		$d2 = "{62BE5D10-60EB-11d0-BD3B-00A0C911CE86}" ascii wide
		$d3 = "{55272A00-42CB-11CE-8135-00AA004BB851}" ascii wide
		$d4 = "SYSTEM\\ControlSet001\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\000" ascii wide nocase
		$d5 = "HardwareInformation.AdapterString" ascii wide
		$d6 = "HardwareInformation.qwMemorySize" ascii wide

	condition:
		uint16(0)==0x5a4d and ((1 of ($q*) and 1 of ($d*)) or 3 of ($d*))
}

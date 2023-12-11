import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_References_SecTools
{
	meta:
		author = "ditekSHen"
		description = "Detects executables referencing many IR and analysis tools"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "procexp.exe" nocase ascii wide
		$s2 = "perfmon.exe" nocase ascii wide
		$s3 = "autoruns.exe" nocase ascii wide
		$s4 = "autorunsc.exe" nocase ascii wide
		$s5 = "ProcessHacker.exe" nocase ascii wide
		$s6 = "procmon.exe" nocase ascii wide
		$s7 = "sysmon.exe" nocase ascii wide
		$s8 = "procdump.exe" nocase ascii wide
		$s9 = "apispy.exe" nocase ascii wide
		$s10 = "dumpcap.exe" nocase ascii wide
		$s11 = "emul.exe" nocase ascii wide
		$s12 = "fortitracer.exe" nocase ascii wide
		$s13 = "hookanaapp.exe" nocase ascii wide
		$s14 = "hookexplorer.exe" nocase ascii wide
		$s15 = "idag.exe" nocase ascii wide
		$s16 = "idaq.exe" nocase ascii wide
		$s17 = "importrec.exe" nocase ascii wide
		$s18 = "imul.exe" nocase ascii wide
		$s19 = "joeboxcontrol.exe" nocase ascii wide
		$s20 = "joeboxserver.exe" nocase ascii wide
		$s21 = "multi_pot.exe" nocase ascii wide
		$s22 = "ollydbg.exe" nocase ascii wide
		$s23 = "peid.exe" nocase ascii wide
		$s24 = "petools.exe" nocase ascii wide
		$s25 = "proc_analyzer.exe" nocase ascii wide
		$s26 = "regmon.exe" nocase ascii wide
		$s27 = "scktool.exe" nocase ascii wide
		$s28 = "sniff_hit.exe" nocase ascii wide
		$s29 = "sysanalyzer.exe" nocase ascii wide
		$s30 = "CaptureProcessMonitor.sys" nocase ascii wide
		$s31 = "CaptureRegistryMonitor.sys" nocase ascii wide
		$s32 = "CaptureFileMonitor.sys" nocase ascii wide
		$s33 = "Control.exe" nocase ascii wide
		$s34 = "rshell.exe" nocase ascii wide
		$s35 = "smc.exe" nocase ascii wide

	condition:
		uint16(0)==0x5a4d and 4 of them
}

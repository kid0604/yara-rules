rule INDICATOR_TOOL_ANT_InviZzzible
{
	meta:
		author = "ditekSHen"
		description = "Detect InviZzzible"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\\\.\\pipe\\task_sched_se" fullword wide
		$s2 = "\\\\\\.\\NPF_NdisWanIp" fullword wide
		$s3 = /--action --(dtt|mra|user-input|cfg|dan|evt|pid|exc|wmi|tsh)/ fullword wide
		$s4 = "cuckoo_%lu.ini" fullword wide
		$s5 = "sandbox evasion" wide nocase
		$s6 = "UnbalancedStack" fullword ascii
		$s7 = "process_with_long_name" fullword ascii
		$s8 = "DelaysAccumulation" fullword ascii
		$s9 = "PidReuse" fullword ascii
		$s10 = "DeadAnalyzer" fullword ascii
		$s11 = "SleepDummyPatch" fullword ascii
		$s12 = "AudioDeviceAbsence" fullword ascii
		$s14 = "\\\\.\\PhysicalDrive%u" fullword ascii
		$s15 = "\"countermeasures\":" ascii
		$s16 = "_%.02u%.02u%.02u_%.02u%.02u%.02u.html" ascii
		$f1 = ".?AVHyperV@SandboxEvasion@@" ascii
		$f2 = ".?AVJoebox@SandboxEvasion@@" ascii
		$f3 = ".?AVKVM@SandboxEvasion@@" ascii
		$f4 = ".?AVMisc@SandboxEvasion@@" ascii
		$f5 = ".?AVParallels@SandboxEvasion@@" ascii
		$f6 = ".?AVQEMU@SandboxEvasion@@" ascii
		$f7 = ".?AVSandboxie@SandboxEvasion@@" ascii
		$f8 = ".?AVVBOX@SandboxEvasion@@" ascii
		$f9 = ".?AVVirtualPC@SandboxEvasion@@" ascii
		$f10 = ".?AVVMWare@SandboxEvasion@@" ascii
		$f11 = ".?AVWine@SandboxEvasion@@" ascii
		$f12 = ".?AVXen@SandboxEvasion@@" ascii

	condition:
		uint16(0)==0x5a4d and (6 of ($s*) or 4 of ($f*) or (2 of ($f*) and 2 of ($s*)))
}

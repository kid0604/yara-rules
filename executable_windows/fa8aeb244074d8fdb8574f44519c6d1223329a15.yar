import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_EXE_SandboxComputerNames
{
	meta:
		author = "ditekSHen"
		description = "Detects executables containing possible sandbox analysis VM names"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "bee7370c-8c0c-4" fullword ascii wide nocase
		$s2 = "desktop-nakffmt" fullword ascii wide nocase
		$s3 = "win-5e07cos9alr" fullword ascii wide nocase
		$s4 = "b30f0242-1c6a-4" fullword ascii wide nocase
		$s5 = "desktop-vrsqlag" fullword ascii wide nocase
		$s6 = "desktop-d019gdm" fullword ascii wide nocase
		$s7 = "desktop-wi8clet" fullword ascii wide nocase
		$s8 = "server1" fullword ascii wide nocase
		$s9 = "lisa-pc" fullword ascii wide nocase
		$s10 = "john-pc" fullword ascii wide nocase
		$s11 = "desktop-b0t93d6" fullword ascii wide nocase
		$s12 = "desktop-1pykp29" fullword ascii wide nocase
		$s13 = "desktop-1y2433r" fullword ascii wide nocase
		$s14 = "wileypc" fullword ascii wide nocase
		$s15 = "6c4e733f-c2d9-4" fullword ascii wide nocase
		$s16 = "ralphs-pc" fullword ascii wide nocase
		$s17 = "desktop-wg3myjs" fullword ascii wide nocase
		$s18 = "desktop-7xc6gez" fullword ascii wide nocase
		$s19 = "desktop-5ov9s0o" fullword ascii wide nocase
		$s20 = "oreleepc" fullword ascii wide nocase
		$s21 = "archibaldpc" fullword ascii wide nocase
		$s22 = "julia-pc" fullword ascii wide nocase
		$s23 = "compname_5076" fullword ascii wide nocase
		$s24 = "desktop-vkeons4" fullword ascii wide nocase
		$s25 = "NTT-EFF-2W11WSS" fullword ascii wide nocase

	condition:
		uint16(0)==0x5a4d and 10 of them
}

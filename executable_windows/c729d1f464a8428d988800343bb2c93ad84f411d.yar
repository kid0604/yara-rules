import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_SandboxUserNames_alt_2
{
	meta:
		author = "ditekSHen"
		description = "Detects executables containing possible sandbox analysis VM usernames"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "15pb" fullword ascii wide nocase
		$s2 = "7man2" fullword ascii wide nocase
		$s3 = "stella" fullword ascii wide nocase
		$s4 = "f4kh9od" fullword ascii wide nocase
		$s5 = "willcarter" fullword ascii wide nocase
		$s6 = "biluta" fullword ascii wide nocase
		$s7 = "ehwalker" fullword ascii wide nocase
		$s8 = "hong lee" fullword ascii wide nocase
		$s9 = "joe cage" fullword ascii wide nocase
		$s10 = "jonathan" fullword ascii wide nocase
		$s11 = "kindsight" fullword ascii wide nocase
		$s12 = "malware" fullword ascii wide nocase
		$s13 = "peter miller" fullword ascii wide nocase
		$s14 = "petermiller" fullword ascii wide nocase
		$s15 = "phil" fullword ascii wide nocase
		$s16 = "rapit" fullword ascii wide nocase
		$s17 = "r0b0t" fullword ascii wide nocase
		$s18 = "cuckoo" fullword ascii wide nocase
		$s19 = "vm-pc" fullword ascii wide nocase
		$s20 = "analyze" fullword ascii wide nocase
		$s21 = "roslyn" fullword ascii wide nocase
		$s22 = "vince" fullword ascii wide nocase
		$s23 = "test" fullword ascii wide nocase
		$s24 = "sample" fullword ascii wide nocase
		$s25 = "mcafee" fullword ascii wide nocase
		$s26 = "vmscan" fullword ascii wide nocase
		$s27 = "mallab" fullword ascii wide nocase
		$s28 = "abby" fullword ascii wide nocase
		$s29 = "elvis" fullword ascii wide nocase
		$s30 = "wilbert" fullword ascii wide nocase
		$s31 = "joe smith" fullword ascii wide nocase
		$s32 = "hanspeter" fullword ascii wide nocase
		$s33 = "johnson" fullword ascii wide nocase
		$s34 = "placehole" fullword ascii wide nocase
		$s35 = "tequila" fullword ascii wide nocase
		$s36 = "paggy sue" fullword ascii wide nocase
		$s37 = "klone" fullword ascii wide nocase
		$s38 = "oliver" fullword ascii wide nocase
		$s39 = "stevens" fullword ascii wide nocase
		$s40 = "ieuser" fullword ascii wide nocase
		$s41 = "virlab" fullword ascii wide nocase
		$s42 = "beginer" fullword ascii wide nocase
		$s43 = "beginner" fullword ascii wide nocase
		$s44 = "markos" fullword ascii wide nocase
		$s45 = "semims" fullword ascii wide nocase
		$s46 = "gregory" fullword ascii wide nocase
		$s47 = "tom-pc" fullword ascii wide nocase
		$s48 = "will carter" fullword ascii wide nocase
		$s49 = "angelica" fullword ascii wide nocase
		$s50 = "eric johns" fullword ascii wide nocase
		$s51 = "john ca" fullword ascii wide nocase
		$s52 = "lebron james" fullword ascii wide nocase
		$s53 = "rats-pc" fullword ascii wide nocase
		$s54 = "robot" fullword ascii wide nocase
		$s55 = "serena" fullword ascii wide nocase
		$s56 = "sofynia" fullword ascii wide nocase
		$s57 = "straz" fullword ascii wide nocase
		$s58 = "bea-ch" fullword ascii wide nocase
		$s59 = "wdagutilityaccount" fullword ascii wide nocase
		$s60 = "peter wilson" fullword ascii wide nocase
		$s61 = "hmarc" fullword ascii wide nocase
		$s62 = "patex" fullword ascii wide nocase
		$s63 = "frank" fullword ascii wide nocase
		$s64 = "george" fullword ascii wide nocase
		$s65 = "julia" fullword ascii wide nocase
		$s66 = "heuerzl" fullword ascii wide nocase
		$s67 = "harry johnson" fullword ascii wide nocase
		$s68 = "j.seance" fullword ascii wide nocase
		$s69 = "a.monaldo" fullword ascii wide nocase

	condition:
		uint16(0)==0x5a4d and 10 of them
}

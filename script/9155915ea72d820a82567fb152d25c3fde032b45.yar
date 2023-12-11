import "math"

rule webshell_php_encoded_big
{
	meta:
		description = "Detect the risk of malicious file (phpwebshell)  Rule 19"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$new_php1 = /<\?=[\w\s@$]/ wide ascii
		$new_php2 = "<?php" nocase wide ascii
		$new_php3 = "<script language=\"php" nocase wide ascii
		$php_short = "<?"
		$cpayload1 = /\beval[\t ]*\([^)]/ nocase wide ascii
		$cpayload2 = /\bexec[\t ]*\([^)]/ nocase wide ascii
		$cpayload3 = /\bshell_exec[\t ]*\([^)]/ nocase wide ascii
		$cpayload4 = /\bpassthru[\t ]*\([^)]/ nocase wide ascii
		$cpayload5 = /\bsystem[\t ]*\([^)]/ nocase wide ascii
		$cpayload6 = /\bpopen[\t ]*\([^)]/ nocase wide ascii
		$cpayload7 = /\bproc_open[\t ]*\([^)]/ nocase wide ascii
		$cpayload8 = /\bpcntl_exec[\t ]*\([^)]/ nocase wide ascii
		$cpayload9 = /\bassert[\t ]*\([^)0]/ nocase wide ascii
		$cpayload10 = /\bpreg_replace[\t ]*\(.{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
		$cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload20 = /\bcreate_function[\t ]*\([^)]/ nocase wide ascii
		$cpayload21 = /\bReflectionFunction[\t ]*\([^)]/ nocase wide ascii
		$m_cpayload_preg_filter1 = /\bpreg_filter[\t ]*\([^\)]/ nocase wide ascii
		$m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii

	condition:
		filesize <1000KB and ( any of ($new_php*) or $php_short at 0) and ( any of ($cpayload*) or all of ($m_cpayload_preg_filter*)) and ( filesize >2KB and (math.entropy(500, filesize -500)>=5.7 and math.mean(500, filesize -500)>80 and math.deviation(500, filesize -500,89.0)<23) or (math.entropy(500, filesize -500)>=7.7 and math.mean(500, filesize -500)>120 and math.mean(500, filesize -500)<136 and math.deviation(500, filesize -500,89.0)>65))
}

rule elf_bashlite_auto_alt_1
{
	meta:
		description = "Detect the risk of Botnet Malware Gafgyt Rule 4"
		os = "linux"
		filetype = "executable"

	strings:
		$sequence_0 = { 21d0 3345fc c9 c3 55 }
		$sequence_1 = { e8???????? 89c2 89d0 c1e81f }
		$sequence_2 = { e8???????? 8945ec 837dec00 750b 8b45ec }
		$sequence_3 = { f7d0 21d0 3345fc c9 }
		$sequence_4 = { 750c e8???????? 8b00 83f804 }
		$sequence_5 = { eb0a c785ecefffff00000000 8b85ecefffff c9 c3 }
		$sequence_6 = { 8b85ecefffff c9 c3 55 }
		$sequence_7 = { c1f802 89c2 89d0 01c0 01d0 }
		$sequence_8 = { 85c0 750c c785ecefffff01000000 eb0a c785ecefffff00000000 8b85ecefffff }
		$sequence_9 = { 21d0 3345fc c9 c3 }

	condition:
		7 of them and filesize <274018
}
